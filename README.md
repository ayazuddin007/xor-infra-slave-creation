# xor-infra-slave-creation

Creates a jenkins slave(ec2 instance) with all the required softwares and aws services.


## Features

- Automates the process of creation of jenkins slave instance/machine
- Create a security group with required inbound and outbound ports.
- Creates roles and policies for the ec2 instance(jenkins slave) with the required permissions.


## Requirements:

| Name          | Version         |
| ------------- | ------------- | 
|Terraform    | >= 0.12 |



## Inputs


| Name          | Desription          | Type    |
| ------------- | ------------- | -------- |
| client_name   | name of client             | String  |
| environment   |Environment name eg dev,qa,uat etc.| String  |
| region_name       |  Region name here the slave is to be deployed|	String |           |
| ec2_ami       | search for ami name which contains "wex--amazon-linux-2" and select the latest id available| String |
|vpc_id   | vpc id where the deployment has to happen | String|
|subnet_id | vpc id where the deployment has to happen| String|
|ec2_instance_type | instance type | String |
|aws_region | The region id where deployment will happen | String|


## Usage

To run this example you need to execute:

```bash
  $ terraform init
  $ terraform plan
  $ terraform apply
```

