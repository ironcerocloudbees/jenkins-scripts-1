import jenkins.model.Jenkins
import hudson.model.Item
import nectar.plugins.rbac.strategy.RoleMatrixAuthorizationPlugin
import nectar.plugins.rbac.groups.GroupContainerLocator
import nectar.plugins.rbac.roles.Role
import nectar.plugins.rbac.groups.Group
import hudson.security.Permission

// Set your Jenkins username and item path
def username = "user1"
def itemPath = "folder1/folder2"

def checkingItems(username, itemPath){
    def item = Jenkins.instance.getItemByFullName(itemPath)
    if (item == null) {
        println "❌ Item not found: '${itemPath}'"
        return
    }

    def roleDetails = [] // list of [roleName, groupName, path, contextName, permissions]
    def roleNameDetails = []
    def seenRoleKeys = [] as Set  // To avoid duplicates: roleName + context + groupName

    println "Gathering RBAC roles for user '${username}' in item '${item.fullName}' and all inherited scopes..."

    def current = item
    while (current != null) {
        def contextLabel = (current == Jenkins.instance) ? "<root>" : current.fullName
        def groupContainer = (current == Jenkins.instance)
            ? RoleMatrixAuthorizationPlugin.getInstance().getRootProxyGroupContainer()
            : GroupContainerLocator.locate(current)

        if (groupContainer == null) {
            println "⚠️ No group container found at '${contextLabel}'"
            current = (current instanceof Item) ? current.getParent() : null
            continue
        }

        // Build group and parent mappings
        def groupMap = groupContainer.getGroups().collectEntries { [(it.name): it] }
        def parentMap = [:].withDefault { [] }

        groupContainer.getGroups().each { group ->
            group.getGroups().each { nested ->
                parentMap[nested] << group.name
            }
        }

        // Find user's direct groups
        def userGroups = groupContainer.getGroups().findAll { g ->
            g.metaClass.respondsTo(g, "getUsers") && g.getUsers().contains(username)
        }

        // Resolve full nested paths
        def visitedPaths = [] as Set
        userGroups.each { group ->
            def start = group.name
            def stack = [[start]]

            while (!stack.isEmpty()) {
                def path = stack.pop()
                def currentGroup = path[-1]
                visitedPaths << path

                parentMap[currentGroup].each { parent ->
                    if (!path.contains(parent)) {
                        stack.push(path + [parent])
                    }
                }
            }
        }

        // Collect roles and permissions
        visitedPaths.each { path ->
            def reversed = path.reverse()
            reversed.each { groupName ->
                def group = groupMap[groupName]
                if (group) {
                    def roles = group.getAllRoles()
                    roles.each { roleName ->
                        def key = "${roleName}@${contextLabel}@${groupName}"
                        if (seenRoleKeys.contains(key)) return
                        seenRoleKeys << key

                        try {
                            if(!roleNameDetails.contains(roleName)){
                                def role = new Role(roleName)
                                def perms = role.getPermissionProxies().collect { "${it.group.title} / ${it.name}" }
                                roleDetails << [
                                    roleName   : roleName,
                                    groupName  : groupName,
                                    path       : reversed.join(" → "),
                                    context    : contextLabel,
                                    permissions: perms
                                ]
                                roleNameDetails << roleName
                            }
                        } catch (Exception e) {
                            println "⚠️ Could not resolve role '${roleName}': ${e.message}"
                        }
                    }
                }
            }
        }

        // Move up
        current = (current instanceof Item) ? current.getParent() : null
        if (current == Jenkins.instance) break
    }

    // ✅ Final output
    if (roleDetails.isEmpty()) {
        println "❌ No roles found for user '${username}' in '${item.fullName}' or inherited contexts."
        return
    }

    println "\nRBAC Role & Permission Summary for '${username}' (including inherited scopes):\n"

    roleDetails.each { entry ->
        println "🔹 Role: ${entry.roleName}"
        println "   • From Group: ${entry.groupName}"
        println "   • Group Path: ${entry.path}"
        println "   • Context: ${entry.context}"
        println "   • Permissions:"
        entry.permissions.each { println "       - ${it}" }
        println ""
    }
}

def checkRoot(username) {
    def config = RoleMatrixAuthorizationPlugin.getConfig()
    def allGroups = config.getGroups()

    // Build lookup maps
    def groupMap = allGroups.collectEntries { [(it.name): it] }
    def parentMap = [:].withDefault { [] }
    allGroups.each { group ->
        group.getGroups().each { nested ->
            parentMap[nested] << group.name
        }
    }

    // Find all directly assigned groups
    def userGroups = allGroups.findAll { g ->
        g.metaClass.respondsTo(g, "getUsers") && g.getUsers().contains(username)
    }

    if (userGroups.isEmpty()) {
        println "❌ User '${username}' is not a member of any configured group."
        return
    }

    // Traverse group ancestry and record roles and permissions
    def visitedPaths = [] as Set
    def roleDetails = []  // list of [roleName, groupName, fullPath, permissionList]
    def roleNameDetails = []

    userGroups.each { group ->
        def start = group.name
        def stack = [[start]]

        while (!stack.isEmpty()) {
            def path = stack.pop()
            def currentGroupName = path[-1]

            visitedPaths << path

            parentMap[currentGroupName].each { parent ->
                if (!path.contains(parent)) {
                    stack.push(path + [parent])
                }
            }
        }
    }

    // Collect roles + permissions per path
    visitedPaths.each { path ->
        def reversed = path.reverse()  // from top-level → direct group
        reversed.each { groupName ->
            def group = groupMap[groupName]
            if (group) {
                def roles = group.getAllRoles()
                roles.each { roleName ->
                    try {
                        if(!roleNameDetails.contains(roleName)){
                            def role = new Role(roleName)
                            def perms = role.getPermissionProxies().collect { "${it.group.title} / ${it.name}" }
                            roleDetails << [
                                roleName     : roleName,
                                fromGroup    : groupName,
                                fullPath     : reversed.join(" → "),
                                permissions  : perms
                            ]
                            roleNameDetails << roleName
                        }
                    } catch (Exception e) {
                        println "⚠️ Could not resolve role '${roleName}': ${e.message}"
                    }
                }
            }
        }
    }

    // Print summary
    roleDetails.each { entry ->
        println "🔹 Role: ${entry.roleName}"
        println "   • From Group: ${entry.fromGroup}"
        println "   • Group Path: ${entry.fullPath}"
        println "   • Context: Jenkins"
        println "   • Permissions:"
        entry.permissions.each { println "       - ${it}" }
        println ""
    }
}

checkingItems(username, itemPath)
checkRoot(username)

return