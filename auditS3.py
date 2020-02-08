import boto3
import json
import argparse
import ast
from datetime import datetime
import csv

def s3(profile, bucketName, filename, awsAccountId):
    print("starting AWS S3 audits")
    profile_session = boto3.session.Session(profile_name=profile)
    iam_client = profile_session.client('iam')
    s3_client = profile_session.client('s3')
    
    polForUser = getPolicyStatementsForUser(iam_client)
    polForRole = getPolicyStatementsForRole(iam_client)
    badS3FromUserAndGroupPolicies = getAdmins(polForUser)
    badS3FromRolePolicies = getAdmins(polForRole)
    badS3FromBucketPolicies = scrapeBucketForNonCompliantUserAccessThroughBucketPolicy(s3_client, awsAccountId, bucketName)
    print("Finished AWS S3 audits")    

    print("Writing out results")    
    generateCSV(badS3FromUserAndGroupPolicies, "IAM", filename)
    generateCSV(badS3FromRolePolicies, "IAM", filename)
    generateCSV(badS3FromBucketPolicies, "S3", filename)    
    
    return badS3FromUserAndGroupPolicies + badS3FromRolePolicies + badS3FromBucketPolicies


def scrapeBucketForNonCompliantUserAccessThroughBucketPolicy(s3_client, forAwsAccount, name=None):
    allowedAccount = forAwsAccount
    listofNonCompliantBuckets = []
    vulnerableBucket = {"bucketName":None, "reason":None}
    allBucketNames = []
    reason = None

    if type(name) == list:
        allBucketNames += name

    if type(name) == str:
        allBucketNames.append(name)

    if not name:
        print("[+] No user supplied bucket name. Fetching all bucket names to audit")
        allBucketNames = []
        allBucketNames = s3_client.list_buckets()   
        allBucketNames = [bucketDetails.get('Name') for bucketDetails in allBucketNames.get('Buckets')] 
    
    for bucketName in allBucketNames:
        reason = None
        found = False      
        try:        
            allowedPrincipal = "arn:aws:iam::{0}:user/{1}-s3".format(allowedAccount,bucketName)
            policy = json.loads(s3_client.get_bucket_policy(Bucket=bucketName).get('Policy'))

            print("[+] Processing bucket " + bucketName + " ================= Bucket policy Found [" +u'\u2713' +"]")
            
            for item in policy.get('Statement'):
                found = False
                reason = None
                principal = []

                if type(item.get('Principal')) == dict:                
                    #for k,v in policy.get('Statement')[0].get('Principal').items():
                    for k,v in item.get('Principal').items():
                        if type(v) == str:
                            principal.append(v)
                        elif type(v) == list:
                            for eachItem in v:
                                principal.append(eachItem)

                else:
                    principal = [item.get('Principal')]
                
                for principalFound in principal:
                    #print(principalFound)
                    if principalFound == '*':
                        #print("Non compliant bucket")
                        found = True
                        reason = "Principal:*"

                    elif principalFound != allowedPrincipal:
                        found = True
                        reason = "extra users"
                                        
                    if found: 
                        vulnerableBucket.update({"bucketName":bucketName, "reason":reason})
                        listofNonCompliantBuckets.append(vulnerableBucket.copy())                    
                        break
                    
                if found:
                    break

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print("[+] Processing bucket " + bucketName + " ================= Bucket policy Found [" +u'\u2717' +"]")
                continue 

    return listofNonCompliantBuckets   
            

def getAdmins(listOfPolicyDics):
    nonCompliantS3User = []
    adminFound =  None
    allowedS3Operations = ["s3:GetObject","s3:PutObject","s3:DeleteObject"]
    s3ActionFound = False
    isUserPolicy = False

    for item in listOfPolicyDics:
        isUserPolicy = False
        allowedResources = []
        item = ast.literal_eval(json.dumps(item)) # to handle the unicode strings in keys and values
        adminFound = False
        printMessage = item.get('policyName') or item.get('policyArn')        

        print("[+] Processing "+printMessage)
        listOfStatements = item.get('statements')
                
        if item.get('Entity').get('UserName'):
            isUserPolicy = True
            
            allowedResources.append("arn:aws:s3:::{0}".format(item.get('Entity').get('UserName')[:-3] if item.get('Entity').get('UserName').lower().endswith('-s3') else item.get('Entity').get('UserName')))

            allowedResources.append("arn:aws:s3:::{0}/*".format(item.get('Entity').get('UserName')[:-3] if item.get('Entity').get('UserName').lower().endswith('-s3') else item.get('Entity').get('UserName')))
        
        for statement in listOfStatements:
            adminFound = False
            if statement.get('Effect').title() == 'Allow':
                rawAction = statement.get('Action')
                rawResource = statement.get('Resource')

                if not rawAction or not rawResource:
                    print("[!] Did not find Action or Resource...skipping this statement")
                    continue

                action = []
                resource = []

                # normalize to a common form. List of actions and resources
                if type(rawAction) == str:
                    action.append(rawAction)
                else:
                    action = rawAction

                if type(rawResource) == str:
                    resource.append(rawResource)
                else:
                    resource = rawResource

                s3ActionFound = False
                for actionValue in action:
                    if 's3:*' == actionValue.lower():
                        nonCompliantS3User.append({'policyName':item.get('policyName'), 'details':item.get('Entity'), 'reason':'s3:*'})
                        s3ActionFound = True
                    
                    elif 's3' in actionValue.lower() and actionValue not in allowedS3Operations:
                        nonCompliantS3User.append({'policyName':item.get('policyName'), 'details':item.get('Entity'), 'reason':'extra permissions => ' + str(actionValue)})
                        s3ActionFound = True
                
                if isUserPolicy:
                    for resourceValue in resource:
                        if ("arn:aws:s3:::" in resourceValue or ("*" in resourceValue and s3ActionFound)) and resourceValue not in allowedResources:
                            nonCompliantS3User.append({'policyName':item.get('policyName'),'details':item.get('Entity'), 'reason':'extra buckets => ' + str(resourceValue)})

    return nonCompliantS3User


def getPolicyStatementsForRole(iam_client, name=None):
    typeOfEntity = 'RoleName'
    listOfAllPolicyArns = []
    allPolicyStatements = []
    listOfAllPolicyNames = []
    allRoleNames = []
    policyDic = {'policyName':None, 'statements':[]}

    if type(name) == list:
        allRoleNames += name

    if type(name) == str:
        allRoleNames.append(name)

    if not name:
        print("[+] No user supplied role name. Fetching all role names to audit")
        allRoles = []
        marker = ''
        while True:
            responseListRoles = iam_client.list_roles(Marker=marker) if marker else iam_client.list_roles()
            allRoles += responseListRoles.get('Roles')
            truncatedListRoles = responseListRoles.get('IsTruncated')
            if not truncatedListRoles:
                print("[+] Found all role names !")
                break
            marker = responseListRoles.get('Marker')        
            print("Found truncated at marker " + marker)

        allRoleNames = [item.get('RoleName') for item in allRoles]
    
    for name in allRoleNames:
        listOfAllPolicyNames = []
        listOfAllPolicyArns = []
        print("\n[+] Processing role: {0}".format(name))
        try:        
            # inline policies
            print("[*] Processing inline policies")
            paginator = iam_client.get_paginator('list_role_policies')
            res = paginator.paginate(RoleName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllPolicyNames += res.build_full_result().get('PolicyNames')

            for eachPolicyName in listOfAllPolicyNames:
                print("[-] Processing "+eachPolicyName)
                res = iam_client.get_role_policy(RoleName=name, PolicyName=eachPolicyName)
                if res.get('ResponseMetadata').get('HTTPStatusCode') == 200:            
                    statement = res.get('PolicyDocument').get('Statement')
                    policyStatement = []

                    # normalize to a common form. List of statements
                    if type(statement) == str or type(statement) == dict:
                        policyStatement.append(dict(statement))
                    else:
                        policyStatement = statement
                    # making the below dic just to make it compatiblle with the already existing getAdmins(), otherwise the below is not really needed (if the respective changes are done to getAdmin() of coruse)
                    policyDic.update({'policyName':eachPolicyName, 'statements':policyStatement, 'Entity':{'RoleName':name}})
                    allPolicyStatements.append(policyDic.copy())

            # attached policies
            print("[*] Processing attached policies")
            paginator = iam_client.get_paginator('list_attached_role_policies')
            res = paginator.paginate(RoleName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllPolicyArns += [item.get('PolicyArn') for item in res.build_full_result().get('AttachedPolicies')]

            allPolicyStatements += getListOfAttachedPolicyStatements(iam_client, listOfAllPolicyArns, typeOfEntity, name)

        except Exception as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print("[!] NoSuchEntity error while processing: {0} : Moving to the next item".format(name))
                continue
            else:
                print("[!] Some other error while processing: {0} : Breaking out of the system".format(name))
                print(e.response['Error']['Code'])

    return allPolicyStatements


'''
Returns : a list of ALL policy statements found for the given group/groups
Arguments: can take an individual group name or a list of group names or nothing. In case of nothing, returns list of policy statements for all the groups found in the given account
Known errors: proceeds gives the error code and proceeds with the next group name.
Unknown errors: exits while displaying the error message
'''
def getPolicyStatementsForGroup(iam_client, name=None):
    typeOfEntity = 'GroupName'
    listOfAllPolicyArns = []
    allPolicyStatements = []
    listOfAllPolicyNames = []
    allGroupNames = []
    policyDic = {'policyName':None, 'statements':[]}

    if type(name) == list:
        allGroupNames += name
    
    if type(name) == str:
        allGroupNames.append(name)

    if not name:
        print("[+] No user supplied group name. Fetching all group names to audit")
        allGroups = []
        marker = ''
        while True:
            responseListGroups = iam_client.list_groups(Marker=marker) if marker else iam_client.list_groups()
            allGroups += responseListGroups.get('Groups')
            truncatedListGroups = responseListGroups.get('IsTruncated')
            if not truncatedListGroups:
                print("[+] Found all group names !")
                break
            marker = responseListGroups.get('Marker')        
            print("Found truncated at marker " + marker)

        allGroupNames = [item.get('GroupName') for item in allGroups]
    
    for name in allGroupNames:    
        listOfAllPolicyNames = []
        listOfAllPolicyArns = []
        print("\n[+] Processing group: {0}".format(name))        
        try:        
            # inline policies
            print("[*] Processing inline policies")
            paginator = iam_client.get_paginator('list_group_policies')
            res = paginator.paginate(GroupName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllPolicyNames += res.build_full_result().get('PolicyNames')
            
            for eachPolicyName in listOfAllPolicyNames:
                print("[-] Processing "+eachPolicyName)
                res = iam_client.get_group_policy(GroupName=name, PolicyName=eachPolicyName)
                if res.get('ResponseMetadata').get('HTTPStatusCode') == 200:            
                    statement = res.get('PolicyDocument').get('Statement')
                    policyStatement = []

                    # normalize to a common form. List of statements
                    if type(statement) == str or type(statement) == dict:
                        policyStatement.append(dict(statement))
                    else:
                        policyStatement = statement
                    # making the below dic just to make it compatiblle with the already existing getAdmins(), otherwise the below is not really needed (if the respective changes are done to getAdmin() of coruse)
                    policyDic.update({'policyName':eachPolicyName, 'statements':policyStatement, 'Entity':{'GroupName':name}})
                    allPolicyStatements.append(policyDic.copy())
            
            # attached policies
            print("[+] Processing attached policies")
            paginator = iam_client.get_paginator('list_attached_group_policies')
            res = paginator.paginate(GroupName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllPolicyArns += [item.get('PolicyArn') for item in res.build_full_result().get('AttachedPolicies')]

            allPolicyStatements += getListOfAttachedPolicyStatements(iam_client, listOfAllPolicyArns, typeOfEntity, name)

        except Exception as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print("[!] NoSuchEntity error while processing: {0} : Moving to the next item".format(name))
                continue
            else:
                print("[!] Some other error while processing: {0} : Breaking out of the system".format(name))
                print(e.response['Error']['Code'])

    return allPolicyStatements

'''
Returns : a list of all inline and attached policy statements found for the given user/users
Arguments: can take an individual user name or a list of user names or nothing. In case of nothing, returns list of policy statements for all the users found in the given account
Known errors: proceeds gives the error code and proceeds with the next user name.
Unknown errors: exits while displaying the error message
'''
def getPolicyStatementsForUser(iam_client, name=None):
    typeOfEntity = 'UserName'
    allPolicyStatements = []
    listOfAllPolicyNames = []
    listOfAllPolicyArns = []
    listOfAllGroupsUserBelongsTo = []
    allUserNames = []
    policyDic = {'policyName':None, 'statements':[]}

    if type(name) == list:
        allUserNames += name

    if type(name) == str:
        allUserNames.append(name)

    if not name:
        print("[+] No user supplied user name. Fetching all user names to audit")
        allUsers = []
        marker = ''
        while True:
            responseListUsers = iam_client.list_users(Marker=marker) if marker else iam_client.list_users()
            allUsers += responseListUsers.get('Users')
            truncatedListUsers = responseListUsers.get('IsTruncated')
            if not truncatedListUsers:
                print("[+] Found all user names !")
                break
            marker = responseListUsers.get('Marker')        
            print("Found truncated at marker " + marker)

        allUserNames = [item.get('UserName') for item in allUsers]

    '''Since user may not have an inline or attached policy but may still inherit a policy from the group they belong to and because there is no direct AWS API to fetch that kind of user policy we would need to manage the same manually.'''
    print("[+] Getting all group policies to process inherited policies")
    allGroupPolicies = getPolicyStatementsForGroup(iam_client)
    
    for name in allUserNames:
        listOfAllPolicyNames = []
        listOfAllPolicyArns = []
        listOfAllGroupsUserBelongsTo = []
        print("\n[+] Processing user: {0}".format(name))        
        try:        
            # inline policies
            print("[+] Processing inline policies")
            paginator = iam_client.get_paginator('list_user_policies')
            res = paginator.paginate(UserName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllPolicyNames += res.build_full_result().get('PolicyNames')

            for eachPolicyName in listOfAllPolicyNames:
                print("[-] Processing "+eachPolicyName)
                res = iam_client.get_user_policy(UserName=name, PolicyName=eachPolicyName)
                if res.get('ResponseMetadata').get('HTTPStatusCode') == 200:            
                    statement = res.get('PolicyDocument').get('Statement')
                    policyStatement = []

                    # normalize to a common form. List of statements
                    if type(statement) == str or type(statement) == dict:
                        policyStatement.append(dict(statement))
                    else:
                        policyStatement = statement
                    # making the below dic just to make it compatiblle with the already existing getAdmins(), otherwise the below is not really needed (if the respective changes are done to getAdmin() of coruse)
                    policyDic.update({'policyName':eachPolicyName, 'statements':policyStatement, 'Entity':{'UserName':name}})
                    allPolicyStatements.append(policyDic.copy())

            # attached policies
            print("[+] Processing attached policies")
            paginator = iam_client.get_paginator('list_attached_user_policies')
            res = paginator.paginate(UserName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllPolicyArns += [item.get('PolicyArn') for item in res.build_full_result().get('AttachedPolicies')]

            allPolicyStatements += getListOfAttachedPolicyStatements(iam_client, listOfAllPolicyArns, typeOfEntity, name)

            # for processing the inherited policies of the user
            print("[+] Processing inherited policies")
            allPolicyStatementsTemp = []
            inheritedPolicyStatements = []
            paginator = iam_client.get_paginator('list_groups_for_user')
            res = paginator.paginate(UserName=name, PaginationConfig={'MaxItems': 100000})
            listOfAllGroupsUserBelongsTo = [item.get('GroupName') for item in res.build_full_result().get('Groups')]            
            allPolicyStatementsTemp = [policyStatementDic.copy() for policyStatementDic in allGroupPolicies if policyStatementDic.get('Entity').get('GroupName') in listOfAllGroupsUserBelongsTo]

            for policyStatement in allPolicyStatementsTemp:
                entityCopy = policyStatement.get('Entity').copy()
                entityCopy.update({'inheritedBy':name})
                inheritedPolicyCopy = policyStatement.copy()
                inheritedPolicyCopy.update({'Entity':entityCopy})
                inheritedPolicyStatements.append(inheritedPolicyCopy)

            allPolicyStatements += inheritedPolicyStatements       


        except Exception as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print("[!] NoSuchEntity error while processing: {0} : Moving to the next item".format(name))
                continue
            else:
                print("[!] Some other error while processing: {0} : Breaking out of the system".format(name))
                print(e.response['Error']['Code'])

    return allPolicyStatements


def getListOfAttachedPolicyStatements(iam_client, allPolicyArns=[], itemTypeBeingProcessed=None, itemNameBeingProcessed=None):
    policyDic = {'policyName':None, 'statements':[]}
    allPolicyStatements = []

    try:
        for policyArn in allPolicyArns:
            print("[-] Processing "+policyArn)
            responseGetPolicy = iam_client.get_policy(PolicyArn=policyArn)
            # the below is needed because the above does not give the actually policy statement. So it has to be fetched as done below
            responseGetPolicyVersion = iam_client.get_policy_version(PolicyArn=policyArn, VersionId=responseGetPolicy['Policy']['DefaultVersionId'])
            rawPolicyStatement = responseGetPolicyVersion.get('PolicyVersion').get('Document').get('Statement')
            policyStatement = []

            # normalize to a common form. List of statements
            if type(rawPolicyStatement) == str or type(rawPolicyStatement) == dict:
                policyStatement.append(dict(rawPolicyStatement))
            else:
                policyStatement = rawPolicyStatement

            policyName = policyArn.split('/')[-1]
            policyDic.update({'policyName':policyName, 'statements':policyStatement, 'Entity':{'PolicyArn':policyArn, itemTypeBeingProcessed:itemNameBeingProcessed}})
            
            allPolicyStatements.append(policyDic.copy())

    except Exception as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("Entity does not exist")

    return allPolicyStatements


def generateCSV(data, source, filename):
    tempList = []    
    entityNameToGet = None
    entityIdentifier = None

    if source == 'IAM':
        tempDict = {'PolicyName':None,'entityName':None,'inheritedBy':None,'reason':None}

    if source == 'S3':
        tempDict = {'BucketName':None, 'reason':None}
    
    for item in data:        
        entityIdentifier = None
        entityNameToGet = None
        # tempDict.update({'policyName':item.get('policyName'),'policyArn':item.get('entity').get('PolicyArn'),'groupName':item.get('entity').get('GroupName'),'inheritedBy':item.get('entity').get('inheritedBy'),'reason':item.get('reason')})
        if source == 'IAM':
            if item.get('details').get('GroupName'):
                entityNameToGet = 'GroupName'
                entityIdentifier = ' - Group'
            elif item.get('details').get('UserName'):
                entityNameToGet = 'UserName'
                entityIdentifier = ' - User'
            else:
                entityNameToGet = 'RoleName'
                entityIdentifier = ' - Role'

            tempDict.update({'PolicyName':item.get('policyName'),'entityName':str(item.get('details').get(entityNameToGet)) + entityIdentifier ,'inheritedBy':item.get('details').get('inheritedBy'),'reason':item.get('reason')})
        
        if source == 'S3':
            tempDict.update({'BucketName':item.get('bucketName'),'reason':item.get('reason')})

        t = tempDict.copy()
        print(t)
        tempList.append(t)

    with open(filename, 'a+') as outf:
        writer = csv.DictWriter(outf, tempList[0].keys())
        writer.writeheader()
        for row in tempList:
            writer.writerow(row)


def get_options():    
    bucketName = outfile = custom = accountId = None
    parser = argparse.ArgumentParser(description='AWS S3 Auditor')
    parser.add_argument('profile', metavar='profile', help='profile in ~/.aws/config')
    parser.add_argument('accountId', metavar='accountId', help='AWS account ID for which buecket violations would be evaluated. This is needed because the script is quite opinionated at the moment towards what is considered a violation')
    parser.add_argument('-b','--bucket', metavar='bucketName', help='bucket name that needs to be audited. Default is all buckets', required=False)
    parser.add_argument('-o','--outfile', metavar='outfileName', help='file name to write out the output. File extension does not need to be provided. Default is s3_audit_data_as_on_<current_time_stamp>', required=False)    
    argss = vars(parser.parse_args())   
    
    profile = argss.get('profile')
    accountId = argss.get('accountId')
    bucketName = argss.get('bucketName')
    outfileName = argss.get('outfileName')

    return profile, accountId, bucketName, outfile

if __name__ == "__main__":
    try:        
        profile, accountId, bucketName, outfile = get_options()        
        # writing out to excel sheet
        currentTimeStamp = str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        if outfile:
            filename = outfile+currentTimeStamp +".csv" 
        else:
            filename = "s3_audit_data_as_on_"+currentTimeStamp +".csv"

        s3(profile, bucketName, filename, accountId)

    except Exception as err:        
        print(err)