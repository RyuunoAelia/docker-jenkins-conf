#!groovy

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;

import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.util.Secret

import com.cloudbees.plugins.credentials.domains.Domain;

import jenkins.model.Jenkins

def env = System.getenv()

def config_repo = env['JENKINS_CONFIG_REPO']
def config_repo_branch = env['JENKINS_CONFIG_REPO_BRANCH']

def config_username = env['JENKINS_CONFIG_CHECKOUT_USERNAME']
def config_password = env['JENKINS_CONFIG_CHECKOUT_PASSWORD']

if (config_repo == null) {
  println "JENKINS_CONFIG_REPO environment variable not set, not creating config repo"
  return 0
}

def configRepoPath = "system-configuration-repo"
Credentials configRepo = (Credentials) new StringCredentialsImpl(
  CredentialsScope.SYSTEM,
  configRepoPath,
  "Configuration repository Path",
  Secret.fromString(config_repo)
)

def config_credid = null

if (config_username && config_password) {
  config_credid = "config-checkout"

  println "Add credentials for checkout of config-repo in SYSTEM scope"
  def Credentials creds = (Credentials) new UsernamePasswordCredentialsImpl(
    CredentialsScope.SYSTEM,
    config_credid,
    "Credentials for checkout of config-repo",
    config_username,
    config_password
  )

  SystemCredentialsProvider.getInstance().getStore().addCredentials(Domain.global(), creds)
}

def jobDslScript = new File('/usr/share/jenkins/resources/configure.groovy').text

folder = Jenkins.instance.getItem('admin')
WorkflowJob job = folder.createProject(WorkflowJob, 'configure')
job.definition = new CpsFlowDefinition(jobDslScript, true)
