import jenkins.model.Jenkins;
import java.lang.reflect.Field;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl

import com.cloudbees.plugins.credentials.domains.Domain;
import jenkins.plugins.hipchat.HipChatNotifier.DescriptorImpl;

import hudson.util.Secret

def env = System.getenv()
hipchat_token = env['JENKINS_HIPCHAT_TOKEN']
if (hipchat_token) {
  def hipchatTextCredId = "hipchat-global-token"

  println "Add HipChat token text credentials in GLOBAL scope"
  Credentials hipchatTextc = (Credentials) new StringCredentialsImpl(
    CredentialsScope.GLOBAL,
    hipchatTextCredId,
    "HipChat token for Jenkins",
    Secret.fromString(hipchat_token)
  )
  SystemCredentialsProvider.getInstance().getStore().addCredentials(Domain.global(), hipchatTextc)

  if ( Jenkins.instance.pluginManager.activePlugins.find { it.shortName == "hipchat" } != null ) {
    println "--> setting hipchat plugin"

    def descriptor = Jenkins.instance.getDescriptorByType(jenkins.plugins.hipchat.HipChatNotifier.DescriptorImpl.class)

    // no setters :-(
    // Groovy can disregard object's pivacy anyway to directly access private
    // fields, but we use a different technique 'reflection' this time
    Field[] fld = descriptor.class.getDeclaredFields();
    for(Field f:fld){
      f.setAccessible(true);
      switch (f.getName()) {
        case "v2Enabled"      : f.set(descriptor, true)
                              break
        case "server"         : f.set(descriptor, "api.hipchat.com")
                              break
        case "credentialId"   : f.set(descriptor, hipchatTextCredId)
                              break
        case "room"           : f.set(descriptor, "Jenkins CI")
                              break
        case "sendAs"         : f.set(descriptor, "Jenkins")
                              break
      }
    }
  }
}
