
import os, sys, subprocess
from python_terraform import *
from contextlib import redirect_stdout
import  git
from git import Repo
import boto3
from botocore.exceptions import NoCredentialsError

def delete_temp_instance():
    tmp_key = subprocess.run("wget -q -O - http://169.254.169.254/latest/meta-data/instance-id", shell=True, stdout=subprocess.PIPE)
    Instance_ID= tmp_key.stdout.decode("utf-8").strip()
    print(Instance_ID)
    subprocess.run("aws ec2 stop-instances --region eu-central-1 --instance-ids "+Instance_ID, shell=True)


# encrypt secret file
def encryptSecretFile():
    tmp_key = subprocess.run("aws secretsmanager get-secret-value --secret-id master_key --region eu-central-1 | jq --raw-output '.SecretString' | jq -r '.master'", shell=True, stdout=subprocess.PIPE)
    key = tmp_key.stdout.decode("utf-8").strip()
    subprocess.run("openssl enc -aes-256-cbc -salt -in /home/ec2-user/slave-secrets.yaml -out ./wex-ifcs-slave-creation/common_baseline/files/secret-keys.yaml -k "+key, shell=True)
    execute('init')
    
def plan(action):
    print(action)
    tf = Terraform(working_dir='.',var_file="./terraform.tfvars")
    approve = {'auto-approve': True}
#     os.system("sudo chown jenkins:jenkins *")
    
    if action is "plan" :
        (return_code, stdout, stderr) = tf.plan()
        with open('./plan2.txt', 'w') as f:
            with redirect_stdout(f):
                print (stdout)
        file = open('./plan2.txt', 'r')
        for line in file:
            if 'No changes. Your infrastructure matches the configuration' in line:
                print (line)
                #upload_to_aws('/home/ec2-user/TestSlave/terraform.tfstate', 'aws-lambda-test-python-bucket-1', 'jenkins-slave/terraform.tfstate')
                #delete_temp_instance()
                break
        file.close()
        sys.exit()


def execute_init():
    tf = Terraform(working_dir='.',var_file="./terraform.tfvars")
    approve = {"auto-approve": True}
#     os.system("sudo chown jenkins:jenkins *")
    
    #tf.init()
    return_code, stdout, stderr = tf.init()
    with open(os.open('./init.txt', os.O_CREAT | os.O_WRONLY, 0o777), 'w') as f:
        with redirect_stdout(f):
            print(stdout)
            print(stderr)
    file = open("./init.txt", 'r')
    for line in file:
        if "Terraform has been successfully initialized!" in line:
            print(line)
            break
    file.close()

        
       
      

def execute_plan():
    tf = Terraform(working_dir='.',var_file="./terraform.tfvars")
    approve = {"auto-approve": True}
    
#     os.system("sudo chown jenkins:jenkins *")

            
    #tf.plan()
    return_code, stdout, stderr = tf.plan()
    #print(stdout)
    with open('./plan.txt', 'w') as f:
        with redirect_stdout(f):
            print(stdout) 
            print(stderr)
    file = open("./plan.txt", 'r')
    for line in file:
        if "Plan: 16 to add, 0 to change, 0 to destroy" in line:
            print(line)
            break
    file.close()
        

def execute_apply():
    tf = Terraform(working_dir='.',var_file="./terraform.tfvars")
    approve = {"auto-approve": True}
#     os.system("sudo chown jenkins:jenkins *")
    
    # tf.apply(skip_plan=True)
    return_code, stdout, stderr = tf.apply(skip_plan=True)
    # print(stdout)
    print(stderr)
    with open('./apply.txt', 'w') as f:
        with redirect_stdout(f):
            print(stdout)
            print(stderr)
    file = open("./apply.txt", 'r')
    for line in file:
        if "Apply complete! Resources: 16 added, 0 changed, 0 destroyed" in line:
            print(line)
            break
    file.close()


if __name__ == "__main__":
    #encryptSecretFile()
    
    execute_init()
    execute_plan()
    execute_apply()
    plan('plan')
