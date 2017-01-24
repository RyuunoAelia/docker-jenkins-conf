#!groovy
import javaposse.jobdsl.dsl.DslScriptLoader
import javaposse.jobdsl.plugin.JenkinsJobManagement

def env = System.getenv()

if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "job-dsl" } != null ){
  def jobDslScript = new File("${env('JENKINS_HOME')}/groovy/base-job-dsl.groovy")
  def workspace = new File('.')
  def jobManagement = new JenkinsJobManagement(System.out, [:], workspace)

  new DslScriptLoader(jobManagement).runScript(jobDslScript.text)
}