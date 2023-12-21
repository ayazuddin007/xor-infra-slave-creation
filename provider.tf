provider "aws" {
  region = var.aws_region

  #Tag to go on every resource created by the script
  default_tags {
    tags = {
      Owner = "gl-wfl-devops@gmail.com"
    } 
  
  }

}
