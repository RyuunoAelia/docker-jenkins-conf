import jenkins.*
import jenkins.model.*
import hudson.model.*
import hudson.slaves.*
import hudson.FilePath

import com.cloudbees.hudson.plugins.folder.*;
import com.cloudbees.hudson.plugins.folder.properties.*;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty
import com.cloudbees.plugins.credentials.impl.*;
import com.cloudbees.plugins.credentials.*;
import com.cloudbees.plugins.credentials.domains.*;
import hudson.util.Secret

import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.nodes.JobRestrictionProperty;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.restrictions.job.StartedByMemberOfGroupRestriction;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.restrictions.job.RegexNameRestriction;
import com.synopsys.arc.jenkinsci.plugins.jobrestrictions.util.GroupSelector;
import java.util.List;
import groovy.lang.Binding;

def workspace = this.getBinding().getVariable("build").getWorkspace()

class slaveNodeRestriction {

    def restrictGroupsOnNodes(
        groupNameList,
        nodeList
    ){

        List grouplist = new LinkedList();
        groupNameList.each { groupName ->
            GroupSelector  g = new GroupSelector (groupName);
            grouplist.add(g);
        }

        StartedByMemberOfGroupRestriction startGrpRestr = new StartedByMemberOfGroupRestriction(grouplist, false );
        JobRestrictionProperty jobrestrict = new JobRestrictionProperty(startGrpRestr);

        List restrictlist = new LinkedList();
        restrictlist.add(jobrestrict);

        RetentionStrategy retStrat = new RetentionStrategy.Always()

        //for (aSlave in hudson.model.Hudson.instance.slaves) {
        hudson.model.Hudson.instance.slaves.eachWithIndex { aSlave, index ->
            if (nodeList.contains(index+1)) {
                aSlave.setRetentionStrategy(retStrat);
                aSlave.setNodeProperties(restrictlist);
                aSlave.save()
            }
        }

    }

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

        //for (aSlave in hudson.model.Hudson.instance.slaves) {
        hudson.model.Hudson.instance.slaves.eachWithIndex { aSlave, index ->
            if (nodeList.contains(index+1)) {
                aSlave.setRetentionStrategy(retStrat);
                aSlave.setNodeProperties(restrictlist);
                aSlave.save()
            }
        }

    }
}

class folderCredential {
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
}

// Create new instances
GroovyObject folderCredentialInst = (GroovyObject) folderCredential.newInstance();
GroovyObject slaveNodeRestrictionInst = (GroovyObject) slaveNodeRestriction.newInstance();

// Read config files contents
String teams = new File("${workspace}/teams.list").text
println "-------------------- Credentials -----------------------"
def slavesIndexHash = [:]
teams.eachLine { line ->
    if (line =~ /^[a-zA-Z]/) {
        def team_params  = line.split(';')
        def team_name = team_params[0]
        def team_ldap_group = team_params[1]
        def team_github_group = team_params[2]
        def team_github_token = team_params[3]
        def slave_numbers = team_params[4]
        println "Add credential ${team_github_group} for ${team_name}"
        folderCredentialInst.addFolderUserPasswordCredential(
            team_name,
            "${team_github_group}-token",
            "Github token for ${team_name}",
            team_github_group,
            team_github_token
        )

        String[] strArray = slave_numbers.split(",");
        int[] intSlaveArray = new int[strArray.length];
        for(int i = 0; i < strArray.length; i++) {
            intSlaveArray[i] = Integer.parseInt(strArray[i]);
        }

        intSlaveArray.each {
            if (slavesIndexHash.containsKey(it)) {
                    slavesIndexHash[it].add(team_name)
            } else {
                    slavesIndexHash[it] = [team_name]
            }
        }
    }
}
println "--------------------------------------------------------"

println "-------------------- Slave Access ----------------------"
slavesIndexHash.each{ k, v ->
    println "Grant Access to Slave #${k} for ${v}"
    slaveNodeRestrictionInst.restrictFoldersOnNodes(
        v,
        [k]
    )
}
println "--------------------------------------------------------"
