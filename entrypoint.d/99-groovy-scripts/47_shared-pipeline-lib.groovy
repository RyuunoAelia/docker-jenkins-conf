import jenkins.model.Jenkins

import jenkins.plugins.git.GitSCMSource;

import org.jenkinsci.plugins.workflow.libs.SCMSourceRetriever;
import org.jenkinsci.plugins.workflow.libs.LibraryConfiguration;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;

import com.cloudbees.plugins.credentials.domains.Domain;

import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;

def env = System.getenv()

def pipeline_lib_repo = env['JENKINS_PIPELINE_LIB_REPO']
def pipeline_username = env['JENKINS_PIPELINE_USERNAME']
def pipeline_password = env['JENKINS_PIPELINE_PASSWORD']
def pipeline_repo_ref = env['JENKINS_PIPELINE_REPO_REF']
def pipeline_lib_name = 'system'

if (pipeline_repo_ref == null) {
  pipeline_repo_ref = 'master'
}

def textCredId = null

if (pipeline_username && pipeline_password) {
  textCredId = "system-pipeline-library-creds"
  Credentials pwcglob = (Credentials) new UsernamePasswordCredentialsImpl(
    CredentialsScope.GLOBAL,
    textCredId,
    "Read access on system pipeline shared library repository",
    pipeline_username,
    pipeline_password
  )

  println "Add credentials for pipeline library in GLOBAL scope"
  SystemCredentialsProvider.getInstance().getStore().addCredentials(Domain.global(), pwcglob)
}

if (pipeline_lib_repo) {
  if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "workflow-cps-global-lib" } != null ) {
    println "--> setting shared pipeline library"

    def credId = textCredId

    def inst = Jenkins.getInstance()
    def desc = inst.getDescriptor("org.jenkinsci.plugins.workflow.libs.GlobalLibraries")

    GitSCMSource scm = new GitSCMSource(
      pipeline_lib_name,
      pipeline_lib_repo,
      textCredId,
      "*/${pipeline_repo_ref}",
      "",
      false
    )

    SCMSourceRetriever retriever = new SCMSourceRetriever(scm)

    LibraryConfiguration libconfig = new LibraryConfiguration(
      pipeline_lib_name,
      retriever
    )

    libconfig.setDefaultVersion(pipeline_repo_ref)
    libconfig.setImplicit(false)

    desc.get().setLibraries([libconfig])
    desc.save()
  }
}
