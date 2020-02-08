# AWS S3 Auditor
An *opinionated* s3 auditor. It generates a report of *improper* S3 bucket access. (*'Improper'* means violations benchmarked against the opinions about what's considered secure as per a certain organization, actors involved & the reason/s for the violation. - More details around the opinions/assumptions can be found [nuckingfoob.me](http://www.nuckingfoob.me/audit-aws-s3/index.html) 

    python auditS3.py -h
    usage: auditS3.py [-h] [-b bucketName] [-o outfileName] profile accountId
    
    AWS S3 Auditor
    
    positional arguments:
      profile               profile in ~/.aws/config
      accountId             AWS account ID for which buecket violations would be
                            evaluated. This is needed because the script is quite
                            opinionated at the moment towards what is considered a
                            violation
    
    optional arguments:
      -h, --help            show this help message and exit
      -b bucketName, --bucket bucketName
                            bucket name that needs to be audited. Default is all
                            buckets
      -o outfileName, --outfile outfileName
                            file name to write out the output. File extension does
                            not need to be provided. Default is
                            s3_audit_data_as_on_<current_time_stamp>

### Output interpretation
- Stdout messages are running logs of the script run. They may aid in debugging if needed
- The results of the script run are available in user specified filename or default filename (as csv). The csv may look something like the below snapshot (when opened with a csv reader, like MS Excel, Numbers etc.)
![Sample Report](/sampleReport.png?raw=true "Sample Report")

- There are 4 columns in the report
  - policyName => the policy becasue of which *a certain access* is being given *to a certain entity*
  - entitiyName => the name of the entity that is getting *a certain access*. This could be a user or a group or a role. 
  - inheritedBy => in case of a the entity name being a group or a role, it could be inherited by a user. This filed gives that information
  - reason => why was this violation caused

- Example: In the above screenshot, the 1st row means:
  ##### What
  The entity named auditors, which is basically an IAM group, has been found to be in violation of the S3 security rules (opinionated). 

  ##### How
  Because of the IAM policy named AmazonS3ReadOnlyAccess

  ##### Why
  Becasue the IAM policy, 'AmazonS3ReadOnlyAccess' gives extra (than the ones mentioned in the secure S3 rules) permissions, which is Get:*

  ##### Who
  As a result, the user named <redacted_IAM_user_name>, stands in violation as well. 


### Requirements
- boto3==1.11.13 (tested with the specific version. Others should also however work fine)
- the AWS profile used to do the audit should have (tested with) the SecurityAudit AWS Managed Policy. (Although, there's a smaller subset of the needed policies that can be used as well to achieve the same. The script primarily needs read permissions on s3 & IAM. This has not been tested though)

### Caveats
- Is single threaded at the moment & hence may take a while to finish
- Script checks for only bucket level access (not object level)
- Tested on OSX High Sierra. Should work for Linux & Windows equally well as well

### Todos
☐ make it multi threaded

☐ in order to make it flexible (still opinionated), add support for custom policies to check against for issues

☐ modify to allow running of the script with even smaller set of absolutely needed permissions, instead of the SecurityAudit AWS Managed Policy (being currently used)

☐ add object level checks as well

☐ add support for other output formats, like json, html etc.

☐ upgrade to python3

☐ handle exceptions better

☐ possibly make the output more legible/better organized. Add an impact column to the report as well perhaps

☐ dev comments around the functions to aid legibility
