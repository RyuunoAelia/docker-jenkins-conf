#!groovy

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;

import javaposse.jobdsl.plugin.JenkinsJobManagement
import javaposse.jobdsl.dsl.DslScriptLoader

def env = System.getenv()

def config_repo = env['JENKINS_CONFIG_REPO']
def config_repo_branch = env['JENKINS_CONFIG_REPO_BRANCH']

def config_username = env['JENKINS_CONFIG_CHECKOUT_USERNAME']
def config_password = env['JENKINS_CONFIG_CHECKOUT_PASSWORD']

def jenkins_admin = env['JENKINS_ADMIN_GROUPNAME']

if (config_repo && jenkins_admin) {

  def config_credid = null

  if (config_username && config_password) {
    config_credid = "config-checkout"

    println "Add credentials for checkout of config-repo in SYSTEM scope"
    def Credentials sysTokenCred = (Credentials) UsernamePasswordCredentialsImpl(
      CredentialsScope.SYSTEM,
      config_credid,
      "Credentials for checkout of config-repo",
      config_username,
      config_password
    )

    SystemCredentialsProvider.getInstance().getStore().addCredentials(Domain.global(), sysTokenCred)
  }

//  def jobDslScript = new File('/usr/share/jenkins/resources/configure.groovy').text
//  def workspace = new File('.')
//  def jobManagement = new JenkinsJobManagement(System.out, [:], workspace)
//  println new DslScriptLoader(jobManagement).runScript(jobDslScript)

}


