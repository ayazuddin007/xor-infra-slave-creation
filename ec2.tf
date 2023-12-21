
# Create an instance 
resource "aws_instance" "ansible" {
  ami           = var.ec2_ami # us-west-2
  instance_type = var.ec2_instance_type


  tags = local.ec2_tags

  key_name        = "deployer-key"
  subnet_id = var.subnet_id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile = aws_iam_instance_profile.test_profile.name


  ebs_block_device {
    device_name           = "/dev/xvda"
    volume_size           = "10"
    volume_type           = "gp2"
    encrypted             = true
    delete_on_termination = true
  }


  provisioner "remote-exec" {

    inline = [
      "echo 'Waiting till SSH is ready'"
    ]

    connection {
      type = "ssh"
      user = var.ssh_user
      private_key = file(var.private_key_path)
      host = aws_instance.ansible.private_ip
    }
    
  }

  provisioner "local-exec" {
#     command = "ansible-playbook -i ${aws_instance.ansible.private_ip}, --private-key ${var.private_key_path} setup-baseline.yml -e 'ansible_user=ec2-user file_system_id=${aws_efs_file_system.demo.id}  aws_region=${var.aws_region}'"
#     command = "ansible-playbook -i ${aws_instance.ansible.private_ip}, --private-key ${var.private_key_path} setup-baseline.yml -e 'ansible_user=ec2-user aws_region=${var.aws_region}'"
    command = "ansible-playbook -i ${aws_instance.ansible.private_ip}, --private-key ${var.private_key_path} setup-baseline.yml -e 'ansible_user=ec2-user aws_region=${var.aws_region} SLAVE_IP=${aws_instance.ansible.private_ip} NODE_NAME='slave1'' -e '@slave_extra_vars.json'"
  }
  
  provisioner "local-exec" {

     when = destroy

# command = "sudo chmod 744 /home/ec2-user/terraformSlave/ansible_role/common_baseline/files/delete_slave.sh && sh /home/ec2-user/terraformSlave/ansible_role/common_baseline/files/delete_slave.sh"

command = "sudo java -jar /home/ec2-user/slave/jenkins-cli.jar -s http://18.207.254.76:8080/ -auth admin:admin delete-node slave"


# command = "java -jar ${var.JENKINS_SLAVE_PATH}/jenkins-cli.jar -noCertificateCheck -s ${var.JENKINS_URL} -auth ${var.JENKINS_USERNAME}:${var.JENKINS_PASSWORD} delete-node ${var.NODE_NAME}"


# command = "java -jar '${self.JENKINS_SLAVE_PATH}'/jenkins-cli.jar -noCertificateCheck -s '${self.JENKINS_URL}' -auth '${self.JENKINS_USERNAME}':'${self.JENKINS_PASSWORD}' delete-node '${self.NODE_NAME}'"


}

   lifecycle {
    ignore_changes = [
      ebs_block_device,
      credit_specification,
      hibernation,
      tags,
      tags_all

    ]
  }
}




