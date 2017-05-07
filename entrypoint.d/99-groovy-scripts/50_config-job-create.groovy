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

import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolder;

import jenkins.model.Jenkins;

import hudson.plugins.git.GitSCM;
import hudson.plugins.git.BranchSpec;
import hudson.plugins.git.SubmoduleConfig;
import hudson.plugins.git.extensions.GitSCMExtension;
import java.util.Collections;

import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;

def env = System.getenv()

def config_repo = env['JENKINS_CONFIG_REPO']
def config_repo_ref = env['JENKINS_CONFIG_REPO_REF']
def config_username = env['JENKINS_CONFIG_REPO_USERNAME']
def config_password = env['JENKINS_CONFIG_REPO_PASSWORD']

def gpg_key = env['JENKINS_GPG_PRIVATE_KEY']
def gpg_pass = env['JENKINS_GPG_PRIVATE_KEY_PASSWORD']

if (config_repo == null) {
  println "JENKINS_CONFIG_REPO environment variable not set, not creating config repo"
  return 0
}

folder = Jenkins.instance.getItem('admin')
folderAbs = AbstractFolder.class.cast(folder)
property = folderAbs.getProperties().get(FolderCredentialsProperty.class)
if(property) {
    property.getStore().addCredentials(Domain.global(), c)
} else {
    property = new FolderCredentialsProperty([])
    folderAbs.addProperty(property)
}

credentialStore = property.getStore()

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

  credentialStore.addCredentials(Domain.global(), creds)
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

  credentialStore.addCredentials(Domain.global(), creds)
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

  credentialStore.addCredentials(Domain.global(), creds)
} else {
  println "No Password for GPG Key, consider adding one"
}

def jobDslScript = new File('/usr/share/jenkins/resources/configure.groovy').text

def scm = new GitSCM(
        GitSCM.createRepoList(config_repo, config_credid),
        Collections.singletonList(new BranchSpec("*/${config_repo_ref}")),
        false,
        Collections.<SubmoduleConfig>emptyList(),
        null,
        null,
	Collections.<GitSCMExtension>emptyList()
)

folder = Jenkins.instance.getItem('admin')
FreeStyleProject job = folder.createProject(FreeStyleProject, 'configure')
builder = new SystemGroovy(new StringSystemScriptSource(new SecureGroovyScript(jobDslScript, false)))
ScriptApproval.get().preapprove(jobDslScript, GroovyLanguage.get())
job.getBuildersList().add(builder)
job.setScm(scm)
