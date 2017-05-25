
/*
 * Above this comment a definition of FolderManager Class in string folderManagerDef is injected
 * container start by stcript entrypoint.d/50_config-job-create.groovy
 * (at runtime in $JENKINS_HOME/init.groovy.d/50_config-job-create.groovy)
 * A definition of adminGroupName is also added containing the name of the Jenkins admin group
 */

import hudson.model.Hudson;
import hudson.slaves.RetentionStrategy;

import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;

import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.nodes.JobRestrictionProperty;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.restrictions.job.StartedByMemberOfGroupRestriction;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.restrictions.job.RegexNameRestriction;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.util.GroupSelector;


import hudson.util.Secret;
import hudson.model.FreeStyleProject;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval;
import org.jenkinsci.plugins.scriptsecurity.scripts.languages.GroovyLanguage;
import hudson.plugins.groovy.StringSystemScriptSource;
import hudson.plugins.groovy.SystemGroovy;
import java.util.Collections;

import hudson.plugins.git.GitSCM;
import hudson.plugins.git.BranchSpec;
import hudson.plugins.git.SubmoduleConfig;
import hudson.plugins.git.extensions.GitSCMExtension;

configLoaderDef = '''
                         import java.nio.charset.StandardCharsets;
                         import groovy.util.ConfigSlurper;
                         import java.io.ByteArrayOutputStream;
                         import java.io.File;

                         public class ConfigLoader {
                           Object pgpHelper = null
                           String privateKey = null
                           String keyPassword = null

                           def ConfigLoader(aPgpHelper, aPrivateKey, aKeyPassword) {
                             this.pgpHelper = aPgpHelper
                             this.privateKey = aPrivateKey
                             this.keyPassword = aKeyPassword
                           }

                           def decipher(String cipherTextString) {
                             if (this.privateKey == null) {
                               throw new MissingPropertyException('You tried to call decrypt without setting a gpg Key')
                             }
                             def cipherTextIs = new ByteArrayInputStream(cipherTextString.getBytes(StandardCharsets.UTF_8));
                             def privKeyIn = new ByteArrayInputStream(this.privateKey.getBytes(StandardCharsets.UTF_8))
                             def plainText = new ByteArrayOutputStream()
                             def password = null
                             if (this.keyPassword) {
                               password = this.keyPassword.toCharArray()
                             }
                             this.pgpHelper.decryptFile(cipherTextIs, plainText, privKeyIn, password);
                             return plainText.toString("UTF-8")
                           }
                           def parseConfigFile(String filePath) {
                             // Read config files contents
                             def parser = new ConfigSlurper()

                             parser.setBinding(['decrypt':this.&decipher])
                             return parser.parse(new File(filePath).text)
                           }
                         }

'''

pgpHelperDef = '''
                       import java.io.InputStream;
                       import java.io.OutputStream;
                       import java.security.NoSuchProviderException;
                       import java.security.SecureRandom;
                       import java.io.IOException;
                       import java.io.ByteArrayOutputStream;
                       import java.io.File;

                       import java.security.Security;
                       import java.util.Iterator;

                       import org.bouncycastle.bcpg.ArmoredOutputStream;
                       import org.bouncycastle.jce.provider.BouncyCastleProvider;
                       import org.bouncycastle.openpgp.PGPCompressedData;
                       import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
                       import org.bouncycastle.openpgp.PGPEncryptedData;
                       import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
                       import org.bouncycastle.openpgp.PGPEncryptedDataList;
                       import org.bouncycastle.openpgp.PGPException;
                       import org.bouncycastle.openpgp.PGPLiteralData;
                       import org.bouncycastle.openpgp.PGPObjectFactory;
                       import org.bouncycastle.openpgp.PGPOnePassSignatureList;
                       import org.bouncycastle.openpgp.PGPPrivateKey;
                       import org.bouncycastle.openpgp.PGPPublicKey;
                       import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
                       import org.bouncycastle.openpgp.PGPPublicKeyRing;
                       import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
                       import org.bouncycastle.openpgp.PGPSecretKey;
                       import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
                       import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
                       import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
                       import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
                       import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
                       import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
                       import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
                       import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
                       import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

                       /**
                        * Taken from org.bouncycastle.openpgp.examples
                        *
                        * @author seamans
                        * @author jdamico <damico@dcon.com.br>
                        *
                        */
                       public class PgpHelper {

                       	private static PgpHelper INSTANCE = null;

                       	public static PgpHelper getInstance(){

                       		if(INSTANCE == null) INSTANCE = new PgpHelper();
                       		return INSTANCE;
                       	}


                       	private PgpHelper(){}


                       	public readPublicKey(input) throws IOException, PGPException {
                               input = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(input);
                               PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(input);

                               //
                               // we just loop through the collection till we find a key suitable for encryption, in the real
                               // world you would probably want to be a bit smarter about this.
                               //
                               PGPPublicKey key = null;

                               //
                               // iterate through the key rings.
                               //
                               Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

                               while (key == null && rIt.hasNext()) {
                                   PGPPublicKeyRing kRing = rIt.next();
                                   Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
                                   while (key == null && kIt.hasNext()) {
                                       PGPPublicKey k = kIt.next();

                                       if (k.isEncryptionKey()) {
                                           key = k;
                                       }
                                   }
                               }

                               if (key == null) {
                                   throw new IllegalArgumentException("Can't find encryption key in key ring.");
                               }

                               return key;
                           }

                           /**
                            * Load a secret key ring collection from keyIn and find the secret key corresponding to
                            * keyID if it exists.
                            *
                            * @param keyIn input stream representing a key ring collection.
                            * @param keyID keyID we want.
                            * @param pass passphrase to decrypt secret key with.
                            * @return
                            * @throws IOException
                            * @throws PGPException
                            * @throws NoSuchProviderException
                            */
                           public PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
                           	throws IOException, PGPException, NoSuchProviderException
                           {
                               PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                               	org.bouncycastle.openpgp.PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

                               PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

                               if (pgpSecKey == null) {
                                   return null;
                               }

                               PBESecretKeyDecryptor a = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(pass);

                               return pgpSecKey.extractPrivateKey(a);
                           }

                           /**
                            * decrypt the passed in message stream
                            */
                           @SuppressWarnings("unchecked")
                       	public void decryptFile(InputStream input, OutputStream out, InputStream keyIn, char[] passwd)
                           	throws Exception
                           {
                           	Security.addProvider(new BouncyCastleProvider());
                               input = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(input);
                               PGPObjectFactory pgpF = new PGPObjectFactory(input, new JcaKeyFingerprintCalculator());
                               PGPEncryptedDataList enc;
                               Object o = pgpF.nextObject();
                               //
                               // the first object might be a PGP marker packet.
                               //
                               if (o instanceof  PGPEncryptedDataList) {
                                   enc = (PGPEncryptedDataList) o;
                               } else {
                                   enc = (PGPEncryptedDataList) pgpF.nextObject();
                               }

                               //
                               // find the secret key
                               //
                               Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
                               PGPPrivateKey sKey = null;
                               PGPPublicKeyEncryptedData pbe = null;

                               while (sKey == null && it.hasNext()) {
                                   pbe = it.next();
                                   sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
                               }

                               if (sKey == null) {
                                   throw new IllegalArgumentException("Secret key for message not found.");
                               }

                               PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(sKey);

                               InputStream clear = pbe.getDataStream(b);

                               PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());

                               Object message = plainFact.nextObject();

                               if (message instanceof  PGPCompressedData) {
                                   PGPCompressedData cData = (PGPCompressedData) message;
                                   PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());

                                   message = pgpFact.nextObject();
                               }

                               if (message instanceof  PGPLiteralData) {
                                   PGPLiteralData ld = (PGPLiteralData) message;
                                   InputStream unc = ld.getInputStream();
                                   int ch;
                                   while ((ch = unc.read()) >= 0) {
                                       out.write(ch);
                                   }
                               } else if (message instanceof  PGPOnePassSignatureList) {
                                   throw new PGPException("Encrypted message contains a signed message - not literal data.");
                               } else {
                                   throw new PGPException("Message is not a simple encrypted file - type unknown.");
                               }

                               if (pbe.isIntegrityProtected()) {
                                   if (!pbe.verify()) {
                                   	throw new PGPException("Message failed integrity check");
                                   }
                               }
                           }

                           public void encryptFile(OutputStream out, String fileName,
                               PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck)
                               throws IOException, NoSuchProviderException, PGPException
                           {
                           	Security.addProvider(new BouncyCastleProvider());

                               if (armor) {
                                   out = new ArmoredOutputStream(out);
                               }

                               ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                               PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                                   PGPCompressedData.ZIP);

                               org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData(comData.open(bOut),
                                   PGPLiteralData.BINARY, new File(fileName));

                               comData.close();

                               JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

                               PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

                               JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

                               cPk.addMethod(d);

                               byte[] bytes = bOut.toByteArray();

                               OutputStream cOut = cPk.open(out, bytes.length);

                               cOut.write(bytes);

                               cOut.close();

                               out.close();
                           }

                       }

'''

credentialsManagerDef = """
  import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
  import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
  import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
  import com.cloudbees.plugins.credentials.Credentials;
  import com.cloudbees.plugins.credentials.CredentialsScope;
  import hudson.util.Secret;

  class CredentialsManager {
  
    def CredentialsManager() {
    }

    def createPassword(folderManager, name, descr, username, password) {
      def Credentials creds = (Credentials) new UsernamePasswordCredentialsImpl(
        CredentialsScope.GLOBAL,
        name,
        descr,
        username,
        password
      )
      folderManager.setCredential(creds)
    }

    def createToken(folderManager, name, descr, token) {
      def Credentials creds = (Credentials) new StringCredentialsImpl(
        CredentialsScope.GLOBAL,
        name,
        descr,
        Secret.fromString(token)
      )
      folderManager.setCredential(creds)
    }

    def createSshPrivateKey(folderManager, name, descr, username, key, passphrase) {
      def Credentials creds = (Credentials) new BasicSSHUserPrivateKey(
        CredentialsScope.GLOBAL,
        name,
        username,
        new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(key),
        passphrase,
        descr
      )
      folderManager.setCredential(creds)
    }

    public static get(folderManager, type, id) {
      def typeclass = null
      switch (type) {
        case 'token':
          typeclass = StringCredentialsImpl.class
          break
        case 'password':
          typeclass = UsernamePasswordCredentialsImpl.class
          break
        case 'ssh':
          typeclass = BasicSSHUserPrivateKey.class
          break
        case 'gpg-key':
          typeclass = StringCredentialsImpl.class
          break
        case 'gpg-password':
          typeclass = StringCredentialsImpl.class
          break
        case 'filename':
          typeclass = StringCredentialsImpl.class
          break
      }

      if (typeclass == null) {
        return null
      }
      def allcreds = folderManager.getCredentials(typeclass)
      return allcreds.find { it.id == id }
    }
  
    def getHTTPAuthHeader(folderManager, type, id) {
      def cred = CredentialsManager.get(folderManager, type, id)
      if (cred == null) {
        return null
      }
      switch (type) {
        case 'password':
          return "basic \${cred.username}:\${cred.password}".bytes.encodeBase64.toString()
        case 'token':
          return "token \${cred.secret}"
      }
      return null
    }
  
  }

"""


def workspace = this.getBinding().getVariable("build").getWorkspace()
def credentialsManager = getClass().getClassLoader().parseClass(credentialsManagerDef, "CredentialsManager").newInstance()

def getGitSCMObectFromDef(folderManager, credentialsManager, prefix, scmdef) {
  def credid = null

  if (! scmdef.containsKey('url')) {
    throw new MissingPropertyException('Git SCM Definition does not container url')
  }
  def repo_ref = "master"
  if (scmdef.containsKey('ref')) {
    repo_ref = scmdef.ref
  }
  def checkout_credentials_id = null
  if (scmdef.containsKey('checkout_credentials')) {
    if (scmdef.checkout_credentials.containsKey('type')) {
      checkout_credentials_id = "credentials-repo-checkout-credentials"
      checkout_credentials_descr = "Credentials to checkout credentials repository"
      checkout_credentials_type = scmdef.checkout_credentials.type
      switch (scmdef.checkout_credentials.type) {
        case 'password':
          if (! scmdef.checkout_credentials.containsKey('username')) {
            throw new MissingPropertyException("Checkout Credentials of password type must contain username parameter");
          }
          if (! scmdef.checkout_credentials.containsKey('password')) {
            throw new MissingPropertyException("Checkout Credentials of password type must contain password parameter");
          }
          credentialsManager.createPassword(folderManager, checkout_credentials_id, checkout_credentials_descr, scmdef.checkout_credentials.username, scmdef.checkout_credentials.password)
        break;
        case 'ssh':
          def passphrase = null
          if (! scmdef.checkout_credentials.containsKey('username')) {
            throw new MissingPropertyException("Checkout Credentials of ssh type must contain username parameter");
          }
          if (! scmdef.checkout_credentials.containsKey('key')) {
            throw new MissingPropertyException("Checkout Credentials of ssh type must contain key parameter");
          }
          if (scmdef.checkout_credentials.containsKey('passphrase')) {
            passphrase = scmdef.checkout_credentials.passphrase
          }
          credentialsManager.createSshPrivateKey(folderManager, checkout_credentials_id, checkout_credentials_descr, scmdef.checkout_credentials.username, scmdef.checkout_credentials.key, passphrase)
        break;
        default:
            throw new MissingPropertyException("Unknown type of Checkout credentials: ${scmdef.scan_credentials.type}");
      }
    }
  }

  def scm = new GitSCM(
          GitSCM.createRepoList(scmdef.url, checkout_credentials_id),
          Collections.singletonList(new BranchSpec("*/${repo_ref}")),
          false,
          Collections.<SubmoduleConfig>emptyList(),
          null,
          null,
          Collections.<GitSCMExtension>emptyList()
  )
}

def setScmForJobFromDef(folderManager, credentialsManager, job, idname, scmdef) {
  if (! scmdef.containsKey('type')) {
    throw new MissingPropertyException('Missing type for scm definition')
  }
  def scm = null
  switch (scmdef.type) {
    case "git":
      scm = getGitSCMObectFromDef(folderManager, credentialsManager, idname, scmdef)
      break;
    default:
      throw new MissingPropertyException("Invalid type for scm def \"${scmdef.type}\" is not supported")
  }
  job.setScm(scm)
}

def addCredentialRefreshJob(folderManager, credentialsManager, credentials) {
  def job = folderManager.getOrCreateJob(FreeStyleProject, 'Refresh Credentials')

  def builderList = job.getBuildersList()
  builderList.each {
    builderList.remove(it)
  }

  def jobDslScript = """
    // this class is injected from Admin Configuration Job
    ${pgpHelperDef}
    
    // this class is injected from Admin Configuration Job
    ${configLoaderDef}
    
    // this class is injected from Admin Configuration Job
    ${folderManagerDef}
    
    // this class is injected from Admin Configuration Job
    ${credentialsManagerDef}
    
    
    def gpg_key_password = null
    def gpg_key = null
    def credentialFileName = null
    def folderManager = new FolderManager("${folderManager.getName()}")
    def credList = folderManager.getCredentials(StringCredentialsImpl.class)
    def credentialsManager = new CredentialsManager()
    
    def tmp = null
    
    tmp = credentialsManager.get(folderManager, 'gpg-key', 'gpg-key')
    if (tmp) {
      println "Found GPG key"
      gpg_key = (String)tmp.secret
    }
    
    tmp = credentialsManager.get(folderManager, 'gpg-password', 'gpg-key-password')
    if (tmp) {
      println "Found GPG key password"
      gpg_key_password = (String)tmp.secret
    }
    
    tmp = credentialsManager.get(folderManager, 'filename', 'credentials-file')
    if (tmp) {
      println "Found credential File name"
      credentialFileName = (String)tmp.secret
    }
    
    def workspace = this.getBinding().getVariable("build").getWorkspace()
    
    def pgpHelper = new PgpHelper()
    
    def configLoader = new ConfigLoader(pgpHelper, gpg_key, gpg_key_password)
    config = configLoader.parseConfigFile("\${workspace}/\${credentialFileName}")
    
    for (Map.Entry<String, Map> cred : config) {
      def name = cred.key
      def values = cred.value
    
      def type = "password"
      if (values.containsKey("type")) {
        type = values.type
      }
      def descr = "Credentials Automatically Added by Refresh Credentials Job"
      if (values.containsKey("description")) {
        descr = values.description
      }
    
      switch (type) {
        case "password":
          if (! (values.containsKey("username") && values.containsKey("password"))) {
            println "Credentials \${name} must contain fields 'username' and 'password' or has wrong 'type'"
            continue
          }
          credentialsManager.createPassword(folderManager, name, descr, values.username, values.password)
        break
        case "token":
          if (! (values.containsKey("token"))) {
            println "Credentials \${name} must contain field 'token' or has wrong 'type'"
            continue
          }
          credentialsManager.createToken(foderManager, name, descr, values.token)
        break
        case 'ssh':
          def passphrase = null
          if (values.containsKey("passphrase")) {
            passphrase = values.passphrase
          }
          if (! (values.containsKey("username"))) {
            println "Credentials \${name} must contain field 'username' or has wrong 'type'"
            continue
          }
          if (! (values.containsKey("key"))) {
            println "Credentials \${name} must contain field 'key' or has wrong 'type'"
            continue
          }
          credentialsManager.createSshPrivateKey(folderManager, name, descr, values.username, values.key, passphrase)
        break
      }
    }
"""

  ScriptApproval.get().preapprove(jobDslScript, GroovyLanguage.get())
  builder = new SystemGroovy(new StringSystemScriptSource(new SecureGroovyScript(jobDslScript, false)))
  builderList.add(builder)
  if (credentials.containsKey('gpg_key')) {
    println "Credentials is using a GPG key"
    def Credentials creds = (Credentials) new StringCredentialsImpl(
      CredentialsScope.SYSTEM,
      'gpg-key',
      'GPG Key to decrypt secrets in "Refresh Credentials" job',
      Secret.fromString(credentials.gpg_key)
    )
    folderManager.setCredential(creds)
  }
  if (credentials.containsKey('gpg_key_password')) {
    println "Credentials GPG key has password"
    def Credentials creds = (Credentials) new StringCredentialsImpl(
      CredentialsScope.SYSTEM,
      'gpg-key-password',
      'GPG Key Password for "Refresh Credentials" job',
      Secret.fromString(credentials.gpg_key_password)
    )
    folderManager.setCredential(creds)
  }

  def credentialFile = "credentials.config"
  if (credentials.containsKey('file')) {
    println "Credentials are present in a custom file"
    credentialFile = credentials.file
  }
  def Credentials creds = (Credentials) new StringCredentialsImpl(
    CredentialsScope.SYSTEM,
    'credentials-file',
    'File where to find team credentials',
    Secret.fromString(credentialFile)
  )
  folderManager.setCredential(creds)

  if (credentials.containsKey('scm')) {
    setScmForJobFromDef(folderManager, credentialsManager, job, 'refresh-credentials', credentials.scm)
  }
}

def addAutoGeneratePipeline(folderManager, credentialsManager, scm) {
  def job = folderManager.getOrCreateJob(FreeStyleProject, 'Auto-Generate Pipelines')

  def builderList = job.getBuildersList()
  builderList.each {
    builderList.remove(it)
  }
  if (! scm.containsKey("type") ) {
    println "Missing type for scm skipping"
    return
  }
  def scm_url_val = null
  def scm_org = null
  def scm_team = null
  switch ("${scm.type}") {
    case "github":
      scm_url_val = "'https://api.github.com'"
      if (scm.containsKey('enterprise_api_url')) {
        scm_url_val = "'${scm.enterprise_api_url}'"
      }
      if (scm.containsKey('org')) {
        scm_org = "'${scm.org}'"
      }
      if (scm.containsKey('team')) {
        scm_team = "'${scm.team}'"
      }
      break
    case "gogs":
      if (scm.containsKey('url')) {
        scm_url_val = "'${scm.url}'"
      }
      if (scm.containsKey('org')) {
        scm_org = "'${scm.org}'"
      }
      if (scm.containsKey('team')) {
        scm_team = "'${scm.team}'"
      }
      break
    case "gitlab":
      break
  
    default:
      println "Unsupported scm type ${scm.type}"
      return;
  }
  def checkout_credentials_type = null
  def scan_credentials_type = null
  def checkout_credentials_id = 'checkout-credentials'
  def scan_credentials_id = 'scan-credentials'
  def checkout_credentials_descr = "Credentials to checkout '${folderManager.getName()}' repositories"
  def scan_credentials_descr = "Credentials to scan '${folderManager.getName()}' repositories"

  if (scm.containsKey('checkout_credentials')) {
    if (scm.checkout_credentials.containsKey('type')) {
      checkout_credentials_type = scm.checkout_credentials.type
      switch (scm.checkout_credentials.type) {
        case 'password':
          if (! scm.checkout_credentials.containsKey('username')) {
            throw new MissingPropertyException("Checkout Credentials of password type must contain username parameter");
          }
          if (! scm.checkout_credentials.containsKey('password')) {
            throw new MissingPropertyException("Checkout Credentials of password type must contain password parameter");
          }
          credentialsManager.createPassword(folderManager, checkout_credentials_id, checkout_credentials_descr, scm.checkout_credentials.username, scm.checkout_credentials.password)
        break;
        case 'ssh':
          def passphrase = null
          if (! scm.checkout_credentials.containsKey('username')) {
            throw new MissingPropertyException("Checkout Credentials of ssh type must contain username parameter");
          }
          if (! scm.checkout_credentials.containsKey('key')) {
            throw new MissingPropertyException("Checkout Credentials of ssh type must contain key parameter");
          }
          if (scm.checkout_credentials.containsKey('passphrase')) {
            passphrase = scm.checkout_credentials.passphrase
          }
          credentialsManager.createSshPrivateKey(folderManager, checkout_credentials_id, checkout_credentials_descr, scm.checkout_credentials.username, scm.checkout_credentials.key, passphrase)
        break;
        default:
            throw new MissingPropertyException("Unknown type of Checkout credentials: ${scm.scan_credentials.type}");
      }
    }
  }

  if (scm.containsKey('scan_credentials')) {
    if (scm.scan_credentials.containsKey('type')) {
      scan_credentials_type = scm.scan_credentials.type
      switch (scm.scan_credentials.type) {
        case 'token':
          if (! scm.scan_credentials.containsKey('token')) {
            throw new MissingPropertyException("Scan Credentials of token type must contain token parameter");
          }
          credentialsManager.createToken(folderManager, scan_credentials_id, scan_credentials_descr, scm.scan_credentials.token)
          break;
        case 'password':
          if (! scm.scan_credentials.containsKey('username')) {
            throw new MissingPropertyException("Scan Credentials of password type must contain username parameter");
          }
          if (! scm.scan_credentials.containsKey('password')) {
            throw new MissingPropertyException("Scan Credentials of password type must contain password parameter");
          }
          credentialsManager.createPassword(folderManager, scan_credentials_id, scan_credentials_descr, scm.scan_credentials.username, scm.scan_credentials.password)
        break;
        default:
            throw new MissingPropertyException("Unknown type of Scan credentials: ${scm.scan_credentials.type}");
      }
    }
  }


  def jobDslScript = """
    import jenkins.branch.BranchSource;
    import org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject;
    import com.cloudbees.hudson.plugins.folder.computed.DefaultOrphanedItemStrategy;
    import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
    import groovy.json.JsonSlurper;
    import jenkins.plugins.git.GitSCMSource;
    import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
    
    // this class is injected from Admin Configuration Job
    ${folderManagerDef}
    
    // this class is injected from Admin Configuration job
    ${credentialsManagerDef}
    
    class GithubRepoDetector {
      def api_url = null
      def org = null
      def team = null
      def parser = null
      def scan_credentials_id = null
      def credentials_type = null
      def credentialsManager = null
      def folderManager = null
    
      def GithubRepoDetector(scm_api_url, scm_org, scm_team, folderManager, credentialsManager, credentials_type, scan_credentials_id) {
        this.api_url = scm_api_url
        this.org = scm_org
        this.team = scm_team
        this.folderManager = folderManager
        this.scan_credentials_id = scan_credentials_id
        this.credentials_type = credentials_type
        this.credentialsManager = credentialsManager
        this.parser = new JsonSlurper()
      }
    
      def fetch(path) {
        def url = (this.api_url + '/api/v1/' + path).toURL()
        def requestProperties = [
          'Accept': 'application/json',
        ]
        if (this.credentials_type && this.scan_credentials_id && this.credentialsManager) {
          requestProperties['Authorization'] = this.credentialsManager.getHTTPAuthHeader(this.folderManager, this.credentials_type, this.scan_credentials_id)
        }
        parser.parse(url.newReader(requestProperties: requestProperties))
      }
    
      def getRepos(type, checkout_credentials_id) {
        // TODO manage paging correctly
        def teamObject = this.fetch("orgs/\${this.org}/teams?per_page=100").find{ it.name == this.team}
        def team_repos = this.fetch("teams/\${teamObject.id}/repos?per_page=100")
        def file_repos = this.fetch("search/code?q=org:\${this.org}+filename:Jenkinsfile+path:/").items.findAll{ it.path == 'Jenkinsfile' }
        def filtered = []
        team_repos.each {
          file_repos.each { file_repo ->
            filtered.addAll(team_repos.findAll {
              it.id == file_repo.id
            })
          }
        }
        def return_repos = [:]
        filtered.each {
          def tmp = [:]
          tmp['scm'] = new GitHubSCMSource(it.name, this.api_url, checkout_credentials_id, this.scan_credentials_id, this.org, it.name)
          return_repos[it.name] = tmp
        }
        return return_repos
      }
    }
    
    class GogsRepoDetector {
      def api_url = null
      def org = null
      def team = null
      def parser = null
      def credentials_id = null
      def credentials_type = null
      def credentialsManager = null
      def folderManager = null
    
      def GogsRepoDetector(api_url, scm_org, scm_team, folderManager, credentialsManager, credentials_type, credentials_id) {
        this.api_url = api_url
        this.org = scm_org
        this.team = scm_team
        this.folderManager = folderManager
        this.credentials_id = credentials_id
        this.credentials_type = credentials_type
        this.credentialsManager = credentialsManager
        this.parser = new JsonSlurper()
      }
    
      def fetch(path) {
        def url = (this.api_url + '/api/v1/' + path).toURL()
        def requestProperties = [
          'Accept': 'application/json',
        ]
        if (this.credentials_type && this.credentials_id && this.credentialsManager) {
          requestProperties['Authorization'] = this.credentialsManager.getHTTPAuthHeader(this.folderManager, this.credentials_type, this.credentials_id)
        }
        parser.parse(url.newReader(requestProperties: requestProperties))
      }
    
      def getRepos(type, credentialsId) {
        //def teamObject = this.fetch("orgs/\${this.org}/teams").find{ it.name == this.team}
        //def team_repos = this.fetch("teams/\${teamObject.id}/repos")
        def repos = this.fetch("orgs/\${this.org}/repos")
        // XXX impossible to filter by team repository for now...
        def return_repos = [:]
        repos.each {
          def tmp = [:]
          if (type == 'ssh') {
            tmp['url']= it.ssh_url
          } else {
            tmp['url'] = it.clone_url
          }
          tmp['scm'] = new GitSCMSource(it.name, tmp['url'], credentialsId, "*", "", false)
          return_repos[it.name] = tmp
	}
        return return_repos
      }
    }
    
    //class GitlabRepoDetector {
    //  GitlabRepoDetector(scm) {
    //  }
    //}
    
    def credentialsManager = new CredentialsManager()
    def folderManager = new FolderManager("${folderManager.getName()}")
    
    def detector = null
    switch ("${scm.type}") {
      case "github":
        detector = new GithubRepoDetector(${scm_url_val}, ${scm_org}, ${scm_team}, folderManager, credentialsManager, '${scan_credentials_type}', '${scan_credentials_id}')
        break;
    
      case "gogs":
        detector = new GogsRepoDetector(${scm_url_val}, ${scm_org}, ${scm_team}, folderManager, credentialsManager, '${scan_credentials_type}', '${scan_credentials_id}')
        break;
    
    //  case "gitlab":
    //    detector = new GitlabRepoDetector(${scm_url_val}, ${scm_org}, ${scm_team}, folderManager, credentialsManager, '${scan_credentials_type}', '${scan_credentials_id}')
    //    break;
    }
    
    def repos = detector.getRepos("${checkout_credentials_type}", "${checkout_credentials_id}")
    repos.each { name, conf ->
      def mbpp = folderManager.getOrCreateJob(WorkflowMultiBranchProject, name)
      mbpp.setOrphanedItemStrategy(new DefaultOrphanedItemStrategy(true, '0', '0'))
      mbpp.getSourcesList().add(new BranchSource(conf['scm']));
    }
    
  """
  ScriptApproval.get().preapprove(jobDslScript, GroovyLanguage.get())
  builder = new SystemGroovy(new StringSystemScriptSource(new SecureGroovyScript(jobDslScript, false)))
  builderList.add(builder)
}

def folderManagerClass = getClass().getClassLoader().parseClass(folderManagerDef, "FolderManager");

def adminFolder = folderManagerClass.newInstance('admin')
def credList = adminFolder.getCredentials(StringCredentialsImpl.class)

def gpg_key_password = null
def gpg_key = null
credList.each {
  switch (it.id) {
    case "gpg-key":
      println "Found GPG key"
      gpg_key = (String)it.secret
      break;
    case "gpg-key-password":
      println "Found GPG key password"
      gpg_key_password = (String)it.secret
      break;
  }
}

def pgpHelper = getClass().getClassLoader().parseClass(pgpHelperDef, "PgpHelper").getInstance();
def configLoader = getClass().getClassLoader().parseClass(configLoaderDef, "ConfigLoader").newInstance(pgpHelper, gpg_key, gpg_key_password);
def teams = configLoader.parseConfigFile("${workspace}/teams.config")

def slavesIndexHash = [:]

for (Map.Entry<String, Map> entry: teams) {
  name = entry.key
  config = entry.value

  if (! config.containsKey('scm')) {
    println "Bad Entry for team ${name} missing 'scm' entry"
    continue;
  }
  if (! config.containsKey('ldap_group')) {
    println "Bad Entry for team ${name} missing 'ldap_group' entry"
    continue;
  }
  if (! config.containsKey('jenkins_slave_allocations')) {
    println "Bad Entry for team ${name} missing 'jenkins_slave_allocations' entry"
    continue;
  }
  def folderManager = folderManagerClass.newInstance(name)

  folderManager.setPermissions(config.ldap_group, adminGroupName)
  if (config.containsKey('credentials')) {
    addCredentialRefreshJob(folderManager, credentialsManager, config.credentials)
  }
  addAutoGeneratePipeline(folderManager, credentialsManager, config.scm)

  config.jenkins_slave_allocations.each {
    if (slavesIndexHash.containsKey(it)) {
      slavesIndexHash[it].add(name)
    } else {
      slavesIndexHash[it] = [name]
    }
  }
}

def restrictFoldersOnNodes(
    folderList,
    nodeList
) {
    def regex = /^[${folderList.join('|')}].*/
    RegexNameRestriction regexRestr = new RegexNameRestriction(regex, false );
    JobRestrictionProperty jobrestrict = new JobRestrictionProperty(regexRestr);

    List restrictlist = new LinkedList();
    restrictlist.add(jobrestrict);

    RetentionStrategy retStrat = new RetentionStrategy.Always()

    //for (aSlave in Hudson.instance.slaves) {
    Hudson.instance.slaves.eachWithIndex { aSlave, index ->
        if (nodeList.contains(index+1)) {
            aSlave.setRetentionStrategy(retStrat);
            aSlave.setNodeProperties(restrictlist);
            aSlave.save()
        }
    }
}

slavesIndexHash.each{ k, v ->
  restrictFoldersOnNodes(
    v,
    [k]
  )
}
