#!/bin/bash


DIR="/var/lib/jenkins/.ssh"
FILE="$DIR"/known_hosts

if [ -d "$DIR" ] 
then
    echo "Directory exists." 
    # sudo cp ~/.ssh/known_hosts "$FILE"
    # sudo chown -R jenkins:jenkins /var/lib/jenkins/.ssh

else
    #echo "Directory does not exists."
    sudo mkdir "$DIR"
    sudo touch "$FILE"
    sudo chown -R jenkins:jenkins /var/lib/jenkins/.ssh

fi






# #!/bin/bash


# DIR="/var/lib/jenkins/.ssh"
# FILE="$DIR"/known_hosts

# if [ -d "$DIR" ] 
# then
#    # echo "Directory exists." 
#     sudo cp ~/.ssh/known_hosts "$FILE"
#     sudo chown -R jenkins:jenkins /var/lib/jenkins/.ssh

# else
#     #echo "Directory does not exists."
#     sudo mkdir "$DIR"
#     sudo touch "$FILE"
#     sudo cp ~/.ssh/known_hosts "$FILE"
#     sudo chown -R jenkins:jenkins /var/lib/jenkins/.ssh

# fi
