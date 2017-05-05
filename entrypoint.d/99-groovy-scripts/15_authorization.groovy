#!groovy
import jenkins.model.*
import hudson.security.ProjectMatrixAuthorizationStrategy
import hudson.security.AuthorizationStrategy
import hudson.security.Permission
import jenkins.security.s2m.AdminWhitelistRule

// Enable Slave -> Master Access Control
Jenkins.instance.injector.getInstance(AdminWhitelistRule.class).setMasterKillSwitch(false);
Jenkins.instance.save()

def env = System.getenv()

class AccessList {
  static set(permManager, userOrGroup, permissions) {
    permissions.each {
      permManager.add(Permission.fromId(it), userOrGroup)
    }
  }
}

if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "matrix-auth" } == null ) {
  println "Jenkins matrix-auth plugin is not available, not setting permissions"
  return 1
}

if ( ! Jenkins.instance.isUseSecurity() ) {
  println "Jenkins Security is disabled, not setting permissions"
  return 2
}

println "--> setting project matrix authorization strategy"
strategy = new hudson.security.ProjectMatrixAuthorizationStrategy()

//------------------- anonymous -------------------------------------------
// (view build status only for image access from the README of github)
AccessList.set(strategy, "anonymous",
    [
      "hudson.model.Item.ViewStatus",
    ]
)

AccessList.set(strategy, "authenticated",
    [
      "hudson.model.Hudson.Read",
    ]
)

if (env['JENKINS_ADMIN_GROUPNAME'] != null) {
  def admin = env['JENKINS_ADMIN_GROUPNAME']
  //----------------- Jenkins Admin -----------------------------------------
  strategy.add(Jenkins.ADMINISTER, admin)

  jenkinsAdminPermissions = []
  // plugin 'credentials' permissions
  if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "credentials" } != null ){
    jenkinsAdminPermissions.addAll(["com.cloudbees.plugins.credentials.CredentialsProvider.Create",
                                    "com.cloudbees.plugins.credentials.CredentialsProvider.Delete",
                                    "com.cloudbees.plugins.credentials.CredentialsProvider.ManageDomains",
                                    "com.cloudbees.plugins.credentials.CredentialsProvider.Update",
                                    "com.cloudbees.plugins.credentials.CredentialsProvider.View"])
  }

  // plugin 'gerrit-trigger' permissions
  if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "gerrit-trigger" } != null ){
    jenkinsAdminPermissions.addAll(["com.sonyericsson.hudson.plugins.gerrit.trigger.PluginImpl.ManualTrigger",
                                    "com.sonyericsson.hudson.plugins.gerrit.trigger.PluginImpl.Retrigger"])
  }
  // plugin 'promoted-builds' permissions
  if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "promoted-builds" } != null ){
    jenkinsAdminPermissions.addAll(["hudson.plugins.promoted_builds.Promotion.Promote"])
  }

  AccessList.set(strategy, admin, jenkinsAdminPermissions)
} else {
  println  "environment variable JENKINS_ADMIN_GROUPNAME is not set, not setting administrator permissions"
}

if (env['JENKINS_SWARM_USERNAME'] != null) {
  def swarm = env['JENKINS_SWARM_USERNAME']
  //----------------- Jenkins Swarm (slave node auth) -----------------------------------------
  jenkinsSwarmPermissions = [
    "hudson.model.Computer.Build",
    "hudson.model.Computer.Build",
    "hudson.model.Computer.Configure",
    "hudson.model.Computer.Connect",
    "hudson.model.Computer.Create",
    "hudson.model.Computer.Delete",
    "hudson.model.Computer.Disconnect",
   ]

  jenkinsSwarm = AccessList.set(strategy, swarm, jenkinsSwarmPermissions)
} else {
  println "environment variable JENKINS_SWARM_USERNAME is not set, not setting permissions for automatic slave join"
}

// now set the strategy globally
Jenkins.instance.setAuthorizationStrategy(strategy)
Jenkins.instance.save()
