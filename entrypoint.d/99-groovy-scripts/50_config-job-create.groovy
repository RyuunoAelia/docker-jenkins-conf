#!groovy

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import hudson.util.Secret;

import hudson.model.FreeStyleProject;

import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import hudson.plugins.groovy.StringSystemScriptSource;
import hudson.plugins.groovy.SystemGroovy;

import hudson.plugins.git.GitSCM;
import hudson.plugins.git.BranchSpec;
import hudson.plugins.git.SubmoduleConfig;
import hudson.plugins.git.extensions.GitSCMExtension;
import java.util.Collections;

import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;

folderManagerDef = '''
                      import com.cloudbees.plugins.credentials.CredentialsProvider;
                      import com.cloudbees.hudson.plugins.folder.Folder;
                      import com.cloudbees.hudson.plugins.folder.AbstractFolder;
                      import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
                      import hudson.security.Permission;
                      import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty;
                      import com.cloudbees.plugins.credentials.domains.Domain;
                      import jenkins.model.Jenkins;

                      class FolderManager {

                        String name = null
                        Folder folder = null

                        def FolderManager(String name) {
                          this.name = name
                        }

                        def getOrCreate() {
                          if (this.folder != null) {
                            return this.folder
                          }
                          def inst = Jenkins.getInstance()
                          this.folder = inst.getItem(this.name)

                          // create folder if not exist
                          if (this.folder == null) {
                            println "Creating folder ${this.name}"
                            inst.createProject(Folder, this.name)
                            this.folder = inst.getItem(this.name)
                          }
                          return this.folder
                        }

                        def getProperty(Class clazz) {
                          this.getOrCreate()
                          return AbstractFolder.class.cast(this.folder).getProperties().get(clazz)
                        }

                        def removeProperty(Class clazz) {
                          this.getOrCreate()
                          AbstractFolder.class.cast(this.folder).getProperties().remove(clazz)
                        }

                        def addProperty(property) {
                          this.getOrCreate()
                          AbstractFolder.class.cast(this.folder).addProperty(property)
                        }

                        def setPermissions(devteam, adminteam) {
                          println "Giving developper access to folder ${this.name} to jenkins group ${devteam}"
                          def property = this.getProperty(AuthorizationMatrixProperty.class)

                          // remove property if already exists
                          if(property != null) {
                            this.removeProperty(property.class)
                          }
                          property = new AuthorizationMatrixProperty(
                            [
                              (Permission.fromId('hudson.model.Item.Read')): [devteam, adminteam],
                              (Permission.fromId('hudson.model.Item.Build')): [devteam, adminteam],
                              (Permission.fromId('hudson.model.Item.ViewStatus')): [devteam, adminteam],

			      (Permission.fromId('hudson.model.Item.Create')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Delete')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Configure')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Read')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Discover')): [adminteam],
			      (Permission.fromId('hudson.model.Item.ExtendedRead')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Build')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Workspace')): [adminteam],
			      (Permission.fromId('hudson.model.Item.WipeOut')): [adminteam],
			      (Permission.fromId('hudson.model.Item.Cancel')): [adminteam],
			      (Permission.fromId('hudson.model.Item.ViewStatus')): [adminteam],
                            ]
                          )
                          this.addProperty(property)
                        }

                        def setCredential(creds) {
                          println "Setting credential ${creds.id} in folder ${folder.getName()}"
                          def property = this.getProperty(FolderCredentialsProperty.class)
                          if(property == null) {
                              property = new FolderCredentialsProperty([])
                              this.addProperty(property)
                          }

                          property.getStore().addCredentials(Domain.global(), creds)
                        }

                        def getCredentials(Class clazz) {
                          this.getOrCreate()
                          return CredentialsProvider.lookupCredentials(
                              clazz,
                              this.folder,
                              null,
                              null
                          )
                        }

                        def getOrCreateJob(Class clazz, String name) {
                          this.getOrCreate()
                          def project = this.folder.getItem(name)
                          if (project == null) {
                            println "Creating Job ${name} in Folder ${this.name}"
                            this.folder.createProject(clazz, name)
                            project = this.folder.getItem(name)
                          }
                          return project
                        }
                      }

'''

def env = System.getenv()

def config_repo = env['JENKINS_CONFIG_REPO']
def config_repo_ref = env['JENKINS_CONFIG_REPO_REF']
def config_username = env['JENKINS_CONFIG_REPO_USERNAME']
def config_password = env['JENKINS_CONFIG_REPO_PASSWORD']
def adminGroupName = env['JENKINS_ADMIN_GROUPNAME']
if (adminGroupName == null) {
  println "environment variable JENKINS_ADMIN_GROUPNAME is not set not creating admin folder"
  return 1
}

def gpg_key = env['JENKINS_GPG_PRIVATE_KEY']
def gpg_pass = env['JENKINS_GPG_PRIVATE_KEY_PASSWORD']

if (config_repo == null) {
  println "JENKINS_CONFIG_REPO environment variable not set, not creating config repo"
  return 0
}

def folderManagerClass = getClass().getClassLoader().parseClass(folderManagerDef, "FolderManager");

folderManager = folderManagerClass.newInstance('admin')
folderManager.setPermissions(adminGroupName, adminGroupName)

def config_credid = null

if (config_username && config_password) {
  config_credid = "config-checkout"

  println "Add credentials for checkout of config-repo in GLOBAL scope"
  def Credentials creds = (Credentials) new UsernamePasswordCredentialsImpl(
    CredentialsScope.GLOBAL,
    config_credid,
    "Credentials for checkout of config-repo",
    config_username,
    config_password
  )

  folderManager.setCredential(creds)
} else {
  println "No Username and Password for config repository checkout"
}

if (gpg_key) {
  def gpg_credid = "gpg-key"

  println "Add gpg key in GLOBAL scope"
  def Credentials creds = (Credentials) new StringCredentialsImpl(
    CredentialsScope.GLOBAL,
    gpg_credid,
    "GPG Key to decrypt secrets in config",
    Secret.fromString(gpg_key)
  )

  folderManager.setCredential(creds)
} else {
  println "No GPG Key for Secrets, consider adding one"
}

if (gpg_pass) {
  def gpg_credid = "gpg-key-password"

  println "Add gpg password for key in GLOBAL scope"
  def Credentials creds = (Credentials) new StringCredentialsImpl(
    CredentialsScope.GLOBAL,
    gpg_credid,
    "Password to unlock GPG Key secrets in config",
    Secret.fromString(gpg_pass)
  )

  folderManager.setCredential(creds)
} else {
  println "No Password for GPG Key, consider adding one"
}

def jobDslScript = "adminGroupName = '${adminGroupName}'\n\n" +
                   "folderManagerDef = '''" + folderManagerDef + "'''" +
		   new File('/usr/share/jenkins/resources/configure.groovy').text

def scm = new GitSCM(
        GitSCM.createRepoList(config_repo, config_credid),
        Collections.singletonList(new BranchSpec("*/${config_repo_ref}")),
        false,
        Collections.<SubmoduleConfig>emptyList(),
        null,
        null,
	Collections.<GitSCMExtension>emptyList()
)

FreeStyleProject job = folderManager.getOrCreateJob(FreeStyleProject, 'configure')
job.setScm(scm)
builder = new SystemGroovy(new StringSystemScriptSource(new SecureGroovyScript(jobDslScript, false)))
ScriptApproval.get().preapprove(jobDslScript, GroovyLanguage.get())

builderList = job.getBuildersList()
builderList.each {
   builderList.remove(it)
}
builderList.add(builder)
