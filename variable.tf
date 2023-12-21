variable "ec2_ami" {
    type = string
}

variable "ec2_instance_type" {
    type = string
}

variable "ssh_user" {
    type = string
}

variable "private_key_path" {
    type = string
    default = "/var/lib/jenkins/deployer-key.pem"
#     default = "/home/ec2-user/deployer-key.pem"
}

variable "aws_region" {
  type    = string
  //default = "eu-central-1"
}

variable "vpc_id" {
  type    = string
}

variable "subnet_id" {
  type    = string
}

variable "client_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "region_name" {
  type = string
}

# variable "efs_subnets" {
#   type = list(any)
# }

# variable "NODE_NAME" {
#  type = string
# }

# variable "JENKINS_URL" {
#   type = string
# }

# variable "JENKINS_SLAVE_PATH" {
#   type = string
# }

# variable "JENKINS_USERNAME" {
#   type = string
# }

# variable "JENKINS_PASSWORD" {
#   type = string
# }
