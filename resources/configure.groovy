import hudson.model.Hudson;
import hudson.slaves.RetentionStrategy;

import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
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




def pgpHelperDef = '''
                       import java.io.InputStream;
                       import java.io.OutputStream;
                       import java.security.NoSuchProviderException;
                       import java.security.SecureRandom;
                       import java.io.IOException;
                       import java.io.ByteArrayOutputStream;
                       import java.io.File;

                       import java.security.Security;
                       import java.util.Iterator;

                       @Grab('org.bouncycastle:bcpg-jdk15on:1.56')
                       @Grab('org.bouncycastle:bcprov-jdk15on:1.56')

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

def configLoaderDef = '''
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
                             return parser.parse(new File(filePath).text).config
                           }
                         }
'''

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

                        def FolderManager(name) {
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

                        def setPermissions(devteam) {
			  println this.name
			  println devteam
                          println "Giving developper access to folder ${this.name} to jenkins group ${devteam}"
                          def property = this.getProperty(AuthorizationMatrixProperty.class)

                          // remove property if already exists
                          if(property != null) {
                            this.removeProperty(property.class)
                          }
                          property = new AuthorizationMatrixProperty(
                            [
                              (Permission.fromId('hudson.model.Item.Read')): [devteam],
                              (Permission.fromId('hudson.model.Item.Build')): [devteam],
                              (Permission.fromId('hudson.model.Item.ViewStatus')): [devteam],
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



def workspace = this.getBinding().getVariable("build").getWorkspace()

def getGitSCMObectFromDef(folderManager, prefix, scmdef) {
  def credid = null

  if (! scmdef.containsKey('url')) {
    throw new MissingPropertyException('Git SCM Definition does not container url')
  }
  def repo_ref = "master"
  if (scmdef.containsKey('ref')) {
    repo_ref = scmdef.repo_ref
  }

  if (scmdef.containsKey('username') && scmdef.containsKey('password')) {
    credid = "creds-${prefix}-checkout"

    println "Repository uses Credentials"
    def Credentials creds = (Credentials) new UsernamePasswordCredentialsImpl(
      CredentialsScope.GLOBAL,
      scmdef.url,
      "Credentials for checkout of \"${job.getName()}\"",
      scmdef.username,
      scmdef.password
    )

    folderManager.setCredential(creds)
  }

  def scm = new GitSCM(
          GitSCM.createRepoList(scmdef.url, credid),
          Collections.singletonList(new BranchSpec("*/${repo_ref}")),
          false,
          Collections.<SubmoduleConfig>emptyList(),
          null,
          null,
          Collections.<GitSCMExtension>emptyList()
  )
}

def setScmForJobFromDef(folderManager, job, idname, scmdef) {
  if (! scmdef.containsKey('type')) {
    throw new MissingPropertyException('Missing type for scm definition')
  }
  def scm = null
  switch (scmdef.type) {
    case "git":
      scm = getGitSCMObectFromDef(folderManager, idname, scmdef)
      break;
    default:
      throw new MissingPropertyException("Invalid type for scm def \"${scmdef.type}\" is not supported")
  }
  job.setScm(scm)
}

def addCredentialRefreshJob(folderManager, credentials) {
  def job = folderManager.getOrCreateJob(FreeStyleProject, 'Refresh Credentials')

  builderList = job.getBuildersList()
  builderList.each {
    builderList.remove(it)
  }

  def jobDslScript = """import jenkins.model.Jenkins"""

  ScriptApproval.get().preapprove(jobDslScript, GroovyLanguage.get())
  builder = new SystemGroovy(new StringSystemScriptSource(new SecureGroovyScript(jobDslScript, false)))
  builderList.add(builder)
  if (credentials.containsKey('gpg_key')) {
    println "Credentials is using a GPG key"
    def Credentials creds = (Credentials) new StringCredentialsImpl(
      CredentialsScope.GLOBAL,
      'gpg-key',
      'GPG Key to decrypt secrets in "Refresh Credentials" job',
      Secret.fromString(credentials.gpg_key)
    )
    folderManager.setCredential(creds)
  }
  if (credentials.containsKey('gpg_key_password')) {
    println "Credentials GPG key has password"
    def Credentials creds = (Credentials) new StringCredentialsImpl(
      CredentialsScope.GLOBAL,
      'gpg-key-password',
      'GPG Key Password for "Refresh Credentials" job',
      Secret.fromString(credentials.gpg_key_password)
    )
    folderManager.setCredential(creds)
  }
  if (credentials.containsKey('scm')) {
    setScmForJobFromDef(folderManager, job, 'refresh-credentials', credentials.scm)
  }
}

def addAutoGeneratePipeline(folderManager, scm) {
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

  folderManager.setPermissions(config.ldap_group)
  if (config.containsKey('credentials')) {
    addCredentialRefreshJob(folderManager, config.credentials)
  }
  addAutoGeneratePipeline(folderManager, config.scm)

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
