import secrets,string,boto3,sys,time


def add_secret():
    response = client.list_secrets()      # list all existing secrets
    if ('-' in sys.argv[2]):              # condition for environament passphrase
        secret=sys.argv[2].replace('-', '')+'secret'             # compose passphrase using environment name
        if any("environments_secrets_passphrase" in a['Name'] for a in response['SecretList']):       # condition to check if secret id already exists
            update_secret('environments_secrets_passphrase',secret)

        else :
            res = client.create_secret(
                    Name='environments_secrets_passphrase',
                    Description='environment secret keys',
                    SecretString='{"' + sys.argv[2] + '":"' + str(secret) +'"}'
                )


    else:
        if any("git_jfrog_credentials" in a['Name'] for a in response['SecretList']):
            update_secret('git_jfrog_credentials',sys.argv[3])
        else :
            res = client.create_secret(
                    Name='git_jfrog_credentials',
                    Description='git and jfrog admin passwords',
                    SecretString='{"' + sys.argv[2] + '":"' + str(sys.argv[3]) +'"}'
                )



def update_secret(id,secret_value):
    response = client.get_secret_value(
    SecretId=id
        )
    secrets = response['SecretString'].replace('}',',')+'"' + sys.argv[2] + '":"' + str(secret_value) +'"}'
    res = client.update_secret(
        SecretId=id,
        SecretString=secrets
    )


if __name__ == "__main__":
    client = boto3.client('secretsmanager',sys.argv[1])
    time.sleep(5)
    add_secret()

#sys.argv[1]=region sys.argv[2]=key and sys.argv[3]=value except encryption key

