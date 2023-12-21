#Export the IP of instance created
output "private_ip_of_ec2" {
  value = aws_instance.ansible.private_ip
}
