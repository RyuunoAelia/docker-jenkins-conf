# Jenkins Master Container

This repository contains a Docker image that will run a Jenkins Master. The master is configured to not run any jobs, so Jenkins Slaves are mandatory for ease of use this image has the swarm plugin enabled and rights setup to allow nodes to join using a configurable username.

The Jenkins master will discover repositories and automatically create MultiBranchPipeLine Jobs for them.

## Requirements

This Image can be used as-is without any external dependency (except for docker-engine). For best user-experience, it is better to use the following:

- An LDAP server for authentication
- Git Repositories for automatic configuration
- An external email service
- A Docker Volume mounted at `/var/jenkins_home` 
- Port 8080 of the container forwarded to the host and/or a HTTPS reverse proxy.

To setup correctly Jenkins it needs to know its own access URL, this can be setup using environment variable `JENKINS_ROOT_URL` for example setting it to `http://jenkins.example.com`.

The timezone can be setup using `JENKINS_TIMEZONE` an example value is `Europe/Zurich`.

## LDAP Authentication

To configure LDAP Authentication the following Environment variables are used:

- `JENKINS_LDAP_SERVER` hostname (or IP) of the LDAP server. Example `ldap.example.com`
- `JENKINS_LDAP_ROOT_DN` the origin DN of all searches in the LDAP tree. Example : `dc=example,dc=com`
- `JENKINS_LDAP_USER_SEARCH_BASE` appended to the `JENKINS_LDAP_ROOT_DN` it will be the base DN to search all users. Example: `cn=groups`
- `JENKINS_LDAP_USER_SEARCH_FILTER` Filter to apply when searching for users. Example: `uid={0}`
- `JENKINS_LDAP_GROUP_SEARCH_BASE` appended to the `JENKINS_LDAP_ROOT_DN` it will be the base DN to search all groups
- `JENKINS_LDAP_GROUP_SEARCH_FILTER` Filter to apply when searching for groups. Example: `cn={0}`
- `JENKINS_LDAP_MANAGER_USER_DN` User DN Jenkins will use to bind to the LDAP server and perform searches
- `JENKINS_LDAP_MANAGER_USER_PASSWORD`User password Jenkins will use to bind to the LDAP server and perform searches

An LDAP group can be set to be administrator using the variable `JENKINS_ADMIN_GROUPNAME`. This will allow any member of the group to have administrator rights. For the configuration of Jenkins this is mandatory.

## Swarm Setup

The swarm plugin is setup on the Jenkins Master to allow automatic slave joining. Some environment variables are used to control the plugin behaviour.

- `JENKINS_SWARM_USERNAME` The username swarm slaves will use to register with the Master. This is used to grant permissions to the user to modify the slave configuration.
- `JENKINS_SLAVE_AGENT_PORT` Communication port open for swarm clients default value of  `50000` is best left unchanged.

## Email

Email notifications can be enabled with the following variables:

- `JENKINS_MAIL_ADDRESS` The email adresse used by Jenkins to send emails. Example: `jenkins@example.com`
- `JENKINS_MAIL_USER` The username Jenkins will use to login into the mail server to send emails.
- `JENKINS_MAIL_PASSWORD` The password Jenkins will use to login into the mail server to send emails.
- `JENKINS_MAIL_SMTP_HOST` The hostname (or IP) to use to send emails.
- `JENKINS_MAIL_SMTP_SSL` Set this to `true` if the mails should be sent using SSL/TLS.
- `JENKINS_MAIL_SMTP_PORT` The port to use to connect to the mail server. Default value is `25` change it for SSL/TLS.

## Automatic Configuration

This Jenkins installation is made to be configured using files in repositories, there is no need to go into the Jenkins Settings to change anything, not even adding Jobs is necessary since it will discover repositories and create the jobs itself.

A root repository defines [Teams](#teams), each Team will have an SCM (github, gogs, gitlab) with Scan Credentials and Checkout Credentials. Scan Credentials are used to discover repositories and configure a MultiBranchPipeline project for each discovered repository. The [Teams](#teams) can also have a Credentials configuration, that allows them to setup Jenkins Credentials to use in Jobs. Format of configuration files is defined in the relevant section for [Teams](#teams) and [Credentials](#credentials).

- `JENKINS_CONFIG_REPO` The repository with the root configuration file. Currently only HTTP(S) is supported. This repository must contain a file named `teams.config` at its root directory.
- `JENKINS_CONFIG_REPO_REF` The reference to use in the repository, can be a branch name or a tag name.
- `JENKINS_CONFIG_REPO_USERNAME` The username to use to checkout the repository via HTTP(S)
- `JENKINS_CONFIG_REPO_PASSWORD` The password to use to checkout the repository via HTTP(S)

### Teams

The teams configuration file `teams.config` must be present at the root of the `JENKINS_CONFIG_REPO` repository. Here is a full example of configuration file:

```
test_team {
  scm {
    type = "gogs"
    url = "http://gogs.example.com"
    org = "example-for"
    team = "example-team"

    scan_credentials {
      type = "token"
      token = "invalid example"
    }

    checkout_credentials {
      type = "ssh"
      username = "example"
      key = "invalid example"
    }
  }

  credentials {
    gpg_key = "invalid example"
    gpg_key_password = "invalid example"

    scm {
      type = "git"
      url = "ssh://example.com/example-repo.git"

      checkout_credentials {
        type = "ssh"
        username = "example"
        key = "invalid example"
      }
    }
    file = "example.creds"
  }
  ldap_group = "example-group"

  jenkins_slave_allocations = [
    1,
  ]
}
```

`test_team` is a section of the configuration and defines a single team of the same name. Jenkins will create a folder with the same name and put the [Credentials](#credentials) and repositories in that folder. A Team name must be valid variable identifiers so the regex to match the team name si as follow `[a-ZA-Z]([a-zA-Z0-9]-\._)*`.

The configuration file will be any number of definitions like the example above, one per team and/or `scm`.

#### scm

The team has an `scm` associated with it, this `scm` section will configure how the repositories are discovered and configured in Jenkins. Allowed scm types are `github` and `gogs` configuration will slightly differ depending on the scm choosen:

- `github `

  By default, will go use `https://api.github.com` to use GitHub enterprise use the `enterprise_api_url` keyword with the api URL of your GitHub enterprise instance.

  An organization is used to scan for the repositories set the name of the organization with keyword `org`

  The team is used to filter the repositories to the ones the team has access to set the name of the team using the `team` keyword

  Only repositories with a `Jenkinsfile` at the root of the repository will be taken into account.

- `gogs`

  The `url` keywork is mandatory, and must be set to the home URL of your gogs instance

  An organization is used to scan for the repositories set the name of the organization with keyword `org`

  The team is used to filter the repositories to the ones the team has access to set the name of the team using the `team` keyword (not yet implemented in gogs, so for now all repositories the `scan_credentials` have access to will be discovered by Jenkins)

`scan_credentials` and `checkout_credentials` are used to scan for repositories and checkout repositories respectively. The `type` keyword is mandatory, allowed types are `ssh` (checkout only), `token (scan only)`, `password`. see [Credentials](#credentials) for a definition of the credentials entry content.

#### credentials subsection

This section allows to configure the [Credentials](#credentials) source configuration of the team.

`gpg_key` and `gpg_key_password` allow for [Configuration Ciphering](#configuration-ciphering) this defines a key specific for that team, and Jenkins will use it to decipher the configuration of that team. That way each team can have a different GPG key and the Jenkins Master another one.

`scm` is the source repository for the team Credentials, a single repository could contain more than one credentials configuration file using setting the `file` keyword to another value for each team. This section works similarly to the [scm](#scm) section of the `team` definition, except there are no `scan_credentials` only `checkout_credentials`.

`file` the filename in the Credentials configuration repository that contains the [Credentials](#credentials) definition.

#### `ldap_group`

This keyword defines which LDAP group will be mapped to the Jenkins Folder. So a team can be mapped to an LDAP group. This allows for multiple benefits:

1. Disallowing anybody to triggering any job, since only the team members can trigger a Job belonging to the team
2. Disallowing anybody to see the Jobs that do not belong to the team

Actually, the team member will only be able to see the folders belonging to the team so a single team has no idea of how many teams there are.

#### `jenkins_slave_allocations`

This is an array of slaves ID, so that a team can have dedicated slaves to run its Jobs.

### Configuration Ciphering

The configuration file can use Ciphered entries to avoid exposing secrets publicly. There is a global GPG Key used for the Jenkins root configuration file, then the root configuration file specifies a GPG key per team. Each GPG Key can be protected by a password.

The root GPG Key is defined using Environment variables:

- `JENKINS_GPG_PRIVATE_KEY` The private key itself in armored format
- `JENKINS_GPG_PRIVATE_KEY_PASSWORD` An optional Password for unlocking the key

An example usage of Cipered configuration is the following:

```
scm {
  type = "git"
  url = "invalid config"

  checkout_credentials {
    type = "ssh"
    username = "git"
    key = decrypt.call("""
                          -----BEGIN PGP MESSAGE-----
                          Version: GnuPG v1

                          hQEMA2bU45owAu4mAQgAhHMIiN2bm53o3KDXx24rk6Ynm0bfTCI51UV0BWD8+hL6
                          UobskaQQragkM9t95vJSKFTXdZQW8d0yVGC0L+bYVAXb0TLEq4OOCe6kUyI+2dxY
                          a6C1gJwWOrt2v3Ppvot7+PW7iGxQH+7IqWWOkkuL2zhvCMeWjqd8UhMQtQCDb/FU
                          KuePZSDc/bC52HFlSg1UW+ANw3CgxC8RY/m+MxAS7H8TcEHGsrC7zz/uH7q2mnlb
                          HTiwDx/cArMRRFtzDsMpoq2uY1gvv8Hm/um4LoptGW97+Q9StKCM1JxfvNGD7MQT
                          eft31ES795D3KqrMpDMIyBnam7YxLN5MZjucNBrqgtLqAU++uf2XSrfYhF0SP5Tw
                          WK/CfqiKmZODOMUVyE/YDVVXXg307fP/GK93TbaEZ7UaMJ0yuQGZeFgpkF6jO/5V
                          jmF2GRK4fAgMVS5TLVJ8TR5pJbN6BoarrACO4ab0TtadUGQhrCMf3O8DYo+snFfi
                          VOG4O4j5Yf4oZ1hUQNoalk55qKANoRgO2BbtX8+dCiFlNlYn0Q9xDFXEsSzHiL+5
                          NfHAfwt03/mQDNgokKP6h/6tGy7VAc37XsRJ1W+H/CJLNqORY6Et+uSlKMKZjBsR
                          JGLJgvnYefHpX6F97dCS5RJpu0HrbpeyKPzlo+KV8n1G4r9G5AuWlI+NGhhjoSIc
                          nfvb29YZBrzhQRS8wRddR4EdjJvhiSJYMuO+XM9cJWt9wdaM74d5KAszJeTAs2Ac
                          PPWHLX97lUXDO5JPLnuxIZiDr5ZPTOfCDo/GPYf6ZW/PEwSNwINbTtCss7HeLsuK
                          SIhTWLTFP74zxeMy7yS3Gcf8HQwz44XULbc9XhYFBp9U+ls1NomodUCj0r5/v69/
                          xhBTbMympy/Tg15AhDevulj9ryR9eyFBTJrtZe29ohYM3bRg8c0PITEugQkLUOdY
                          kG4YVMrdMpwhKslW08BrT4KCkhaZyK6Uf2seTJ3l5SmRCUzfnZLzmWWwrxbSS3XM
                          BOvVmlWcfyLVQ3g+G+4Q6RDX9S1uEokr9Wjzzi3x8LxL89mR0uvl39DvkeVnMtKT
                          YHMSlDkdu6WHifi+ipLkWyPNf1xF2TRpBhrkxrLuGBOjKQcXDOlV0pK5eTTwgL0c
                          7TO+9bdpFztn7IL/jgFaxNGiKuww9rbYiMhoAI2ZaVb1ejoIWA22wfvZjDO4tK6s
                          nH5jRPe6i+Ij5ikmqAvwQhoV+jUXzlrqcGrjN0dP6NtHDlY6FSTEkk/+qzSCYPSx
                          MYp94xYGnS+vXoU1ZMnLHXY3kGcVySDlSdKZl1o/O89jvZaRP/mByjUMKnSMpLWP
                          lpHTZfisGU60loy4/rAzWD02VGfqApQNcd3GmCmKwRnb+UwIN0TqR0nRvN5DMFBa
                          MrYNA6/mR9++2oAk5PitOP3+5ErIVHByPr8OAg/0sMaon79u/dgPK2Oxmbp/fnyr
                          ggEHUh0lynwe+DjcrneashrXk9MIGraaNK06gmgAj4FynvOC5L1rEh2dpXPcLsyd
                          b1UFLNd6uQLPI8m+brP8DhVXP/6dLlk7G8aHiSCx7U3m4o7Htm9fB26EjKWRieWy
                          ZtXrnFi50GvhXdLFRqGK5km4d5XlAnC1J2jsvVK18qP48Og1jtqJ/Wh6fAq065Zt
                          X5GF9hD6/flqZ/LafaYL4miAiGGcvV3VYmwoCt6pie0jc98nr1LsF9Vix4bLeNHN
                          CMCLFEbllrBm3fztMPeToCtvzsPVKeHc5hJYXJAO1zCZzcDZBITwNdhpvVM5SOBu
                          FNG7uZdzxh8xtMQB+bP/M4ccfTimB76g5wYSjBh/7YeKWsVSS+yH1iwKCe16xluQ
                          QsRGB7crBHzHCMmTHx5sXWwSYa7+SoBYCeuoC3Gf4J6VB+05H8ww8xClzLxMDlBQ
                          PmLHRqX07lDjANUFaxdoWWTYLvyA8lqKs9t0+fRkzFNoTBBkq7OH9Hr40dMKG6bl
                          a0xm4gMCmohmAPUDmF3g4mdNb/KN4YrYBjesKA7+R8/P668TYhJaQtRb9JKxjLj0
                          eTfqWDo8xDJRyqoq1kK95Saf+XTioKbpNAMWUUAKvamLWp1A9Y17N+BfkaM5CjMb
                          vVVT9Wzs/aLb8H+UmmjwlUe0piaQP2uVqIy583PFSj0RtrE1ycqsLgd/Fj3uJA==
                          =EFnH
                          -----END PGP MESSAGE-----
                       """.stripIndent())
  }
}
```

Note the `decrypt.call()` to tell the configuration parser that the field is ciphered and the `.stripIndent()` to allow the text field to be indented with the rest of the configuration. `.stripIndent()` is optional if the text between triple quotes is not indented.

### Credentials

Credentials are configurable like the following example:

```
foo {
  type = "password"
  username = "example"
  password = "example-password"
}

bar {
  type = "ssh"
  username = "example"
  key = "invalid key"
}

baz {
  type = "token"
  token = "invalid token"
}
```

These credentials will be added to Jenkins Credentials Plugin and available in the Jobs using the name given as ID.

## Additionnal Plugins

The image allows for additionnal plugins to be installed during startup of the image.

- `JENKINS_UC` The update center where the plugins will be downloaded. The default value of `https://updates.jenkins.io` should be kept as-is unless you know what you are doing.
- `JENKINS_PLUGINS` a list of `plugin_id`:`plugin_version_number` to use, one by line. Example: `git:3.3.0` for the `git` plugin at version `3.3.0` (already installed in the image).
