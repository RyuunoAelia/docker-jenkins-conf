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

def pipeline_lib_name = env['JENKINS_PIPELINE_LIB_NAME']
def pipeline_lib_repo = env['JENKINS_PIPELINE_LIB_REPO']
def pipeline_username = env['JENKINS_PIPELINE_USERNAME']
def pipeline_password = env['JENKINS_PIPELINE_PASSWORD']
def pipeline_repo_ref = env['JENKINS_PIPELINE_REPO_REF']

if (pipeline_repo_ref == null) {
  pipeline_repo_ref = 'master'
}

def textCredId = null

if (pipeline_username && pipeline_password) {
  textCredId = "pipeline-library-creds"
  Credentials pwcglob = (Credentials) new UsernamePasswordCredentialsImpl(
    CredentialsScope.GLOBAL,
    textCredId,
    "Read access on pipeline shared library",
    pipeline_username,
    pipeline_password
  )

  println "Add credentials for pipeline library in GLOBAL scope"
  SystemCredentialsProvider.getInstance().getStore().addCredentials(Domain.global(), pwcglob)
}

if (pipeline_lib_repo && pipeline_lib_name) {
  if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "workflow-cps-global-lib" } != null ) {
    println "--> setting shared pipeline library"

    def sharedLibRepo = pipeline_lib_repo
    def sharedLibName = pipeline_lib_name
    def credId = textCredId
    def ref = pipeline_repo_ref

    def inst = Jenkins.getInstance()
    def desc = inst.getDescriptor("org.jenkinsci.plugins.workflow.libs.GlobalLibraries")

    GitSCMSource scm = new GitSCMSource(
      sharedLibName,
      sharedLibRepo,
      textCredId,
      "*/${ref}",
      "",
      false
    )

    SCMSourceRetriever retriever = new SCMSourceRetriever(scm)

    LibraryConfiguration libconfig = new LibraryConfiguration(
      sharedLibName,
      retriever
    )

    libconfig.setDefaultVersion(ref)
    libconfig.setImplicit(false)

    desc.get().setLibraries([libconfig])
    desc.save()
  }
}
