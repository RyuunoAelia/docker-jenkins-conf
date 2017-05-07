import jenkins.model.Jenkins;
import hudson.model.Hudson;
import hudson.slaves.RetentionStrategy;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsProvider;

import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.nodes.JobRestrictionProperty;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.restrictions.job.StartedByMemberOfGroupRestriction;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.restrictions.job.RegexNameRestriction;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.util.GroupSelector;

import groovy.util.ConfigSlurper;
import hudson.security.Permission;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;

import hudson.util.Secret;
import com.cloudbees.plugins.credentials.domains.Domain;
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


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
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

import java.nio.charset.StandardCharsets;

// GLOBAL variables used by decipher
gpg_key = null
gpg_key_password = null
def decipher(String cipher) {
  if (gpg_key == null) {
    throw new MissingPropertyException('You tried to call decrypt without setting a gpg Key')
  }
  InputStream ciphered = new ByteArrayInputStream(cipher.getBytes(StandardCharsets.UTF_8));
  InputStream privKeyIn = new ByteArrayInputStream(gpg_key.getBytes(StandardCharsets.UTF_8))
  OutputStream plainText = new ByteArrayOutputStream()
  def passin = null
  if (gpg_key_password) {
    passin = gpg_key_password.toCharArray()
  }
  PgpHelper.getInstance().decryptFile(ciphered, plainText, privKeyIn, passin);
  return plainText.toString("UTF-8")
}

def workspace = this.getBinding().getVariable("build").getWorkspace()

def restrictFoldersOnNodes(
    folderList,
    nodeList
){
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

def addFolderUserPasswordCredential(
        folderName,
        credId,
        credDesc,
        credUser,
        credPassword
    ){
    Credentials pwc = (Credentials) new UsernamePasswordCredentialsImpl(
        CredentialsScope.GLOBAL,
        credId,
        credDesc,
        credUser,
        credPassword
    )
    def inst = Jenkins.getInstance()
    for (folder in inst.getAllItems(Folder.class)) {
        if(folder.name.equals(folderName)){
            AbstractFolder<?> folderAbs = AbstractFolder.class.cast(folder)
            FolderCredentialsProperty property = folderAbs.getProperties().get(FolderCredentialsProperty.class)
            if(property) {
                property.getStore().addCredentials(Domain.global(), pwc)
            } else {
                property = new FolderCredentialsProperty([pwc])
                folderAbs.addProperty(property)
            }
        }
    }
}

def createFolderForTeam(name, ldap_group) {
  println "creating folder for team ${name}"
  def inst = Jenkins.getInstance()
  def folder = inst.getItem(name)
  // create folder if not exist
  if (folder == null) {
    inst.createProject(Folder, name)
    folder = inst.getItem(name)
  }

  println "giving full access to the folder to jenkins group ${ldap_group}"
  def folderAbs = AbstractFolder.class.cast(folder)
  def property = folderAbs.getProperties().get(AuthorizationMatrixProperty.class)
  // remove property if already exists
  if(property != null) {
    folderAbs.getProperties().remove(property)
  }
  property = new AuthorizationMatrixProperty(
    [
      (Permission.fromId('hudson.model.Item.Read')): [ldap_group],
      (Permission.fromId('hudson.model.Item.Build')): [ldap_group],
      (Permission.fromId('hudson.model.Item.ViewStatus')): [ldap_group],
    ]
  )
  folderAbs.addProperty(property)
}

def getGitSCMObectFromDef(folder, prefix, scmdef) {
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

    setCredentialInFolder(folder, creds)
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

def setScmForJobFromDef(folder, job, idname, scmdef) {
  if (! scmdef.containsKey('type')) {
    throw new MissingPropertyException('Missing type for scm definition')
  }
  def scm = null
  switch (scmdef.type) {
    case "git":
      scm = getGitSCMObectFromDef(folder, idname, scmdef)
      break;
    default:
      throw new MissingPropertyException("Invalid type for scm def \"${scmdef.type}\" is not supported")
  }
  job.setScm(scm)
}

def setCredentialInFolder(folder, creds) {
  folderAbs = AbstractFolder.class.cast(folder)
  property = folderAbs.getProperties().get(FolderCredentialsProperty.class)
  if(property) {
      property.getStore().addCredentials(Domain.global(), creds)
  } else {
      property = new FolderCredentialsProperty([])
      folderAbs.addProperty(property)
  }

  credentialStore = property.getStore()
  credentialStore.addCredentials(Domain.global(), creds)
}

def addCredentialRefreshJob(name, credentials) {
  def inst = Jenkins.getInstance()
  def folder = inst.getItem(name)

  FreeStyleProject job = (FreeStyleProject) folder.getItem('Refresh Credentials')

  if (job == null) {
    folder.createProject(FreeStyleProject, 'Refresh Credentials')
    job = (FreeStyleProject) folder.getItem(FreeStyleProject, 'Refresh Credentials')
  }

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
    setCredentialInFolder(folder, creds)
  }
  if (credentials.containsKey('gpg_key_password')) {
    println "Credentials GPG key has password"
    def Credentials creds = (Credentials) new StringCredentialsImpl(
      CredentialsScope.GLOBAL,
      'gpg-key-password',
      'GPG Key Password for "Refresh Credentials" job',
      Secret.fromString(credentials.gpg_key_password)
    )
    setCredentialInFolder(folder, creds)
  }
  if (credentials.containsKey('scm')) {
    setScmForJobFromDef(folder, job, 'refresh-credentials', credentials.scm)
  }
}

def addAutoGeneratePipeline(name, scm) {
  //addFolderUserPasswordCredential(
  //    (String)name,
  //    "${config['github_group']}-token",
  //    "Github token for ${name}",
  //    (String)config['github_group'],
  //    (String)config['github_token']
  //)
}

def folder = Jenkins.instance.getItem('admin')

def credList = CredentialsProvider.lookupCredentials(
    StringCredentialsImpl.class,
    folder,
    null,
    null
);

credList.each {
  switch (it.id) {
    case "gpg-key":
      gpg_key = (String)it.secret
      println "Found GPG key"
      break;
    case "gpg-key-password":
      println "Found GPG key password"
      gpg_key_password = (String)it.secret
      break;
  }
}

// Read config files contents
def parser = new ConfigSlurper()

parser.setBinding(['decrypt':this.&decipher])

def teams = parser.parse(new File("${workspace}/teams.config").text).config

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
  createFolderForTeam(name, config.ldap_group)
  if (config.containsKey('credentials')) {
    addCredentialRefreshJob(name, config.credentials)
  }
  addAutoGeneratePipeline(name, config.scm)

  config.jenkins_slave_allocations.each {
    if (slavesIndexHash.containsKey(it)) {
      slavesIndexHash[it].add(name)
    } else {
      slavesIndexHash[it] = [name]
    }
  }
}

slavesIndexHash.each{ k, v ->
  restrictFoldersOnNodes(
    v,
    [k]
  )
}
