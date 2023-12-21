# create role and policy for ec2 instance

resource "aws_iam_role" "test_role" {
  name = "${var.client_name}-${var.environment}-${var.region_name}-role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
       Name = "${var.client_name}-${var.environment}-${var.region_name}-slave-role"
       Owner = "WFL-DEVops"
  }
}

data "aws_iam_policy" "AmazonEKSClusterPolicy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}
resource "aws_iam_role_policy_attachment" "test-attach-AmazonEKSClusterPolicy" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.AmazonEKSClusterPolicy.arn
}

data "aws_iam_policy" "AmazonDynamoDBFullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}
resource "aws_iam_role_policy_attachment" "test-attach-AmazonDynamoDBFullAccess" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.AmazonDynamoDBFullAccess.arn
}

data "aws_iam_policy" "AmazonEKSWorkerNodePolicy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}
resource "aws_iam_role_policy_attachment" "test-attach-AmazonEKSWorkerNodePolicy" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.AmazonEKSWorkerNodePolicy.arn

}


data "aws_iam_policy" "AmazonEKSServicePolicy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
}
resource "aws_iam_role_policy_attachment" "test-attach-AmazonEKSServicePolicy" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.AmazonEKSServicePolicy.arn
}


data "aws_iam_policy" "AmazonEKS_CNI_Policy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}
resource "aws_iam_role_policy_attachment" "test-attach-AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.AmazonEKS_CNI_Policy.arn
}

data "aws_iam_policy" "AmazonElasticFileSystemFullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonElasticFileSystemFullAccess"
}
resource "aws_iam_role_policy_attachment" "test-attach-AmazonElasticFileSystemFullAccess" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.AmazonElasticFileSystemFullAccess.arn
}

data "aws_iam_policy" "SecretsManagerReadWrite" {
  arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}
resource "aws_iam_role_policy_attachment" "test-attach-SecretsManagerReadWrites" {
  role       = aws_iam_role.test_role.name
  policy_arn = data.aws_iam_policy.SecretsManagerReadWrite.arn
}

resource "aws_iam_role_policy_attachment" "attach-AmazonSSMManagedInstanceCore" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.test_role.name
}


resource "aws_iam_policy" "eks_automation" {
  name        = "${var.client_name}-${var.environment}-${var.region_name}-eks-policy"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:*",
                "cloudformation:ListExports",
                "ec2:AuthorizeSecurityGroupIngress",
                "iam:PutRolePolicy",
                "iam:AddRoleToInstanceProfile",
                "ec2:DescribeVolumeStatus",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:CreateRoute",
                "ec2:DescribeVolumes",
                "cloudformation:UpdateStack",
                "ec2:UnassignPrivateIpAddresses",
                "iam:ListRolePolicies",
                "ec2:DescribeKeyPairs",
                "cloudformation:ListStackResources",
                "iam:ListPolicies",
                "iam:GetRole",
                "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
                "ec2:ImportKeyPair",
                "elasticloadbalancing:CreateTargetGroup",
                "ecr:GetAuthorizationToken",
                "ec2:StopInstances",
                "ec2:CreateVolume",
                "ec2:CreateNetworkInterface",
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:DeleteLoadBalancerListeners",
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "iam:UntagRole",
                "iam:TagRole",
                "ec2:DescribeRegions",
                "cloudformation:UpdateTerminationProtection",
                "iam:PassRole",
                "iam:DeleteRolePolicy",
                "cloudformation:DescribeStackSetOperation",
                "cloudformation:StopStackSetOperation",
                "ec2:DeleteLaunchTemplateVersions",
                "elasticloadbalancing:CreateLoadBalancerPolicy",
                "elasticloadbalancing:CreateLoadBalancer",
                "iam:ListRoles",
                "ec2:DescribeSecurityGroups",
                "elasticloadbalancing:DescribeTargetGroups",
                "iam:UpdateRole",
                "iam:ListGroups",
                "elasticloadbalancing:DeleteListener",
                "iam:GetPolicyVersion",
                "elasticloadbalancing:DetachLoadBalancerFromSubnets",
                "elasticloadbalancing:RegisterTargets",
                "iam:ListServerCertificates",
                "iam:RemoveRoleFromInstanceProfile",
                "cloudformation:DescribeStackResource",
                "cloudformation:UpdateStackSet",
                "ec2:DescribePlacementGroups",
                "elasticloadbalancing:DescribeLoadBalancers",
                "route53:ListResourceRecordSets",
                "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                "ecr:BatchCheckLayerAvailability",
                "iam:GetServerCertificate",
                "cloudformation:DescribeStackInstance",
                "ecr:GetDownloadUrlForLayer",
                "iam:GetAccountSummary",
                "cloudformation:DescribeStackDriftDetectionStatus",
                "ec2:DescribeAddresses",
                "cloudformation:UpdateStackInstances",
                "elasticloadbalancing:CreateListener",
                "iam:AddUserToGroup",
                "ecr:DescribeRepositories",
                "iam:CreatePolicyVersion",
                "ec2:ModifyInstanceAttribute",
                "cloudformation:ListStacks",
                "iam:GetInstanceProfile",
                "ec2:DescribeLaunchTemplateVersions",
                "ec2:CreateLaunchTemplateVersion",
                "ec2:DescribeHosts",
                "kms:ListKeys",
                "cloudformation:ListStackSets",
                "iam:ListPolicyVersions",
                "ec2:DeleteSecurityGroup",
                "elasticloadbalancing:DescribeTargetHealth",
                "iam:ListUsers",
                "ec2:ModifyLaunchTemplate",
                "elasticloadbalancing:ModifyTargetGroup",
                "iam:ListUserTags",
                "iam:GetAccountPasswordPolicy",
                "elasticloadbalancing:ModifyListener",
                "ec2:DescribeInstances",
                "iam:ListRoleTags",
                "ec2:CreateKeyPair",
                "cloudformation:CreateChangeSet",
                "ec2:DescribeSnapshots",
                "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
                "cloudformation:DescribeStackEvents",
                "ec2:StartInstances",
                "ec2:RevokeSecurityGroupEgress",
                "cloudformation:DescribeChangeSet",
                "iam:GetPolicy",
                "ec2:CreateTags",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:DescribeIdFormat",
                "cloudformation:SignalResource",
                "iam:DeleteRole",
                "ec2:RunInstances",
                "ec2:AssignPrivateIpAddresses",
                "autoscaling-plans:*",
                "ec2:RevokeSecurityGroupIngress",
                "cloudformation:GetStackPolicy",
                "cloudformation:DeleteStack",
                "ec2:DescribeSubnets",
                "iam:GetRolePolicy",
                "cloudformation:ValidateTemplate",
                "iam:CreateInstanceProfile",
                "ec2:AttachVolume",
                "cloudformation:CancelUpdateStack",
                "s3:ListBucket",
                "ecr:ListImages",
                "ec2:DescribeVpcAttribute",
                "cloudformation:CreateStackInstances",
                "cloudformation:EstimateTemplateCost",
                "ec2:DescribeAvailabilityZones",
                "iam:ListAttachedGroupPolicies",
                "ec2:DescribeInstanceStatus",
                "iam:DeleteInstanceProfile",
                "ec2:DeleteLaunchTemplate",
                "cloudformation:ListImports",
                "route53:ListHostedZones",
                "elasticloadbalancing:DeleteTargetGroup",
                "ec2:CreateLaunchTemplate",
                "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
                "ec2:DescribeVpcs",
                "kms:ListAliases",
                "iam:ListAccountAliases",
                "iam:GetUser",
                "cloudformation:DeleteStackInstances",
                "route53:GetHostedZone",
                "cloudformation:ListStackInstances",
                "ec2:DescribeVolumesModifications",
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "autoscaling:*",
                "cloudformation:ListStackSetOperationResults",
                "elasticloadbalancing:DeleteLoadBalancer",
                "ec2:DescribeInternetGateways",
                "ec2:DeleteVolume",
                "iam:DetachRolePolicy",
                "ec2:GetLaunchTemplateData",
                "iam:ListAttachedRolePolicies",
                "elasticloadbalancing:DescribeLoadBalancerPolicies",
                "ec2:DescribeAccountAttributes",
                "s3:HeadBucket",
                "cloudformation:CreateStackSet",
                "cloudformation:ExecuteChangeSet",
                "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                "ec2:DescribeRouteTables",
                "ec2:DetachVolume",
                "ec2:ModifyVolume",
                "ec2:DescribeLaunchTemplates",
                "route53:ChangeResourceRecordSets",
                "cloudformation:DescribeStackResources",
                "elasticloadbalancing:DeregisterTargets",
                "ec2:DescribeInstanceCreditSpecifications",
                "cloudformation:DescribeStacks",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "cloudformation:DescribeStackResourceDrifts",
                "cloudformation:GetTemplate",
                "iam:ListGroupsForUser",
                "ecr:BatchGetImage",
                "eks:*",
                "ec2:DeleteKeyPair",
                "cloudformation:DetectStackDrift",
                "ec2:DeleteTags",
                "cloudformation:ListStackSetOperations",
                "elasticloadbalancing:ConfigureHealthCheck",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeDhcpOptions",
                "iam:GetGroup",
                "cloudformation:DeleteChangeSet",
                "cloudformation:DetectStackResourceDrift",
                "iam:RemoveUserFromGroup",
                "elasticloadbalancing:DescribeListeners",
                "ec2:CreateSecurityGroup",
                "iam:ListAttachedUserPolicies",
                "cloudformation:DescribeAccountLimits",
                "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
                "ec2:AuthorizeSecurityGroupEgress",
                "elasticloadbalancing:AttachLoadBalancerToSubnets",
                "ec2:TerminateInstances",
                "s3:PutBucketPublicAccessBlock",
                "ec2:DescribeTags",
                "ec2:DeleteRoute",
                "cloudformation:DeleteStackSet",
                "cloudformation:GetTemplateSummary",
                "elasticloadbalancing:CreateLoadBalancerListeners",
                "ec2:DescribeImages",
                "cloudformation:DescribeStackSet",
                "cloudformation:CreateStack",
                "ec2:AttachNetworkInterface",
                "cloudformation:ListChangeSets",
                "ecr:GetRepositoryPolicy",
                "sqs:*",
                "rds:*",
                "route53:*"
            ],
            "Resource": "*"
        }
    ]
})
tags = {
       Name="${var.client_name}-${var.environment}-${var.region_name}-eks_automation_policy2"
       Owner = "WFL-DEVops"
  }
}

resource "aws_iam_role_policy_attachment" "test-attach-eks_automation" {
  role       = aws_iam_role.test_role.name
  policy_arn = aws_iam_policy.eks_automation.arn
}


resource "aws_iam_policy" "xor-eks-automation" {
  name        = "${var.client_name}-${var.environment}-${var.region_name}-policy"
  description = "A test policy"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "elasticloadbalancing:ModifyListener",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DescribeInstances",
                "iam:ListRoleTags",
                "ec2:CreateKeyPair",
                "iam:PutRolePolicy",
                "ec2:DescribeSnapshots",
                "route53:ListHostedZonesByName",
                "iam:AddRoleToInstanceProfile",
                "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
                "ec2:DescribeVolumeStatus",
                "ec2:StartInstances",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:CreateRoute",
                "ec2:DescribeVolumes",
                "ec2:UnassignPrivateIpAddresses",
                "iam:ListRolePolicies",
                "iam:DeleteOpenIDConnectProvider",
                "ec2:DescribeKeyPairs",
                "iam:ListPolicies",
                "iam:GetRole",
                "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
                "iam:GetPolicy",
                "ec2:ImportKeyPair",
                "ec2:CreateTags",
                "elasticloadbalancing:CreateTargetGroup",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:DescribeIdFormat",
                "ecr:GetAuthorizationToken",
                "iam:DeleteRole",
                "ec2:RunInstances",
                "ec2:StopInstances",
                "ec2:AssignPrivateIpAddresses",
                "autoscaling-plans:*",
                "ec2:CreateVolume",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:CreateNetworkInterface",
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:DeleteLoadBalancerListeners",
                "iam:GetOpenIDConnectProvider",
                "ec2:DescribeSubnets",
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "iam:GetRolePolicy",
                "iam:CreateInstanceProfile",
                "ec2:AttachVolume",
                "iam:UntagRole",
                "iam:TagRole",
                "ec2:DescribeRegions",
                "ecr:ListImages",
                "elasticloadbalancing:RemoveListenerCertificates",
                "ec2:DescribeVpcAttribute",
                "iam:PassRole",
                "ec2:DescribeAvailabilityZones",
                "iam:DeleteRolePolicy",
                "elasticloadbalancing:DescribeListenerCertificates",
                "iam:ListAttachedGroupPolicies",
                "ec2:DeleteLaunchTemplateVersions",
                "elasticloadbalancing:CreateLoadBalancerPolicy",
                "kms:CreateGrant",
                "ec2:DescribeInstanceStatus",
                "iam:DeleteInstanceProfile",
                "ec2:DeleteLaunchTemplate",
                "elasticloadbalancing:CreateLoadBalancer",
                "s3:*",
                "route53:ListHostedZones",
                "iam:ListRoles",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:DeleteTargetGroup",
                "ec2:DescribeSecurityGroups",
                "iam:CreatePolicy",
                "iam:CreateServiceLinkedRole",
                "ec2:CreateLaunchTemplate",
                "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
                "ec2:DescribeVpcs",
                "kms:ListAliases",
                "ecr:*",
                "elasticloadbalancing:DescribeTargetGroups",
                "iam:ListAccountAliases",
                "iam:UpdateRole",
                "iam:GetUser",
                "iam:ListGroups",
                "elasticloadbalancing:DeleteListener",
                "iam:UpdateAssumeRolePolicy",
                "iam:GetPolicyVersion",
                "elasticloadbalancing:DetachLoadBalancerFromSubnets",
                "elasticloadbalancing:RegisterTargets",
                "iam:ListServerCertificates",
                "route53:GetHostedZone",
                "iam:RemoveRoleFromInstanceProfile",
                "ec2:DescribeVolumesModifications",
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "elasticloadbalancing:SetIpAddressType",
                "autoscaling:*",
                "ec2:DescribePlacementGroups",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:SetWebAcl",
                "ec2:DescribeInternetGateways",
                "elasticloadbalancing:DescribeLoadBalancers",
                "ec2:DeleteVolume",
                "iam:DetachRolePolicy",
                "ec2:GetLaunchTemplateData",
                "iam:ListAttachedRolePolicies",
                "elasticloadbalancing:DescribeLoadBalancerPolicies",
                "elasticloadbalancing:CreateRule",
                "route53:ListResourceRecordSets",
                "ec2:DescribeAccountAttributes",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                "ec2:DescribeRouteTables",
                "ecr:BatchCheckLayerAvailability",
                "ec2:DetachVolume",
                "iam:GetServerCertificate",
                "ec2:ModifyVolume",
                "ec2:DescribeLaunchTemplates",
                "ecr:GetDownloadUrlForLayer",
                "route53:ChangeResourceRecordSets",
                "cloudformation:*",
                "elasticloadbalancing:DeregisterTargets",
                "ec2:DescribeInstanceCreditSpecifications",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "acm:DescribeCertificate",
                "elasticloadbalancing:ModifyRule",
                "iam:ListGroupsForUser",
                "ecr:BatchGetImage",
                "elasticloadbalancing:DescribeRules",
                "eks:*",
                "ec2:DeleteKeyPair",
                "iam:GetAccountSummary",
                "ec2:DescribeAddresses",
                "ec2:DeleteTags",
                "elasticloadbalancing:ConfigureHealthCheck",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeDhcpOptions",
                "iam:GetGroup",
                "elasticloadbalancing:RemoveTags",
                "elasticloadbalancing:CreateListener",
                "iam:AddUserToGroup",
                "iam:RemoveUserFromGroup",
                "elasticloadbalancing:DescribeListeners",
                "ec2:DescribeNetworkInterfaces",
                "ec2:CreateSecurityGroup",
                "iam:ListAttachedUserPolicies",
                "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
                "kms:DescribeKey",
                "acm:ListCertificates",
                "ecr:DescribeRepositories",
                "iam:CreatePolicyVersion",
                "ec2:ModifyInstanceAttribute",
                "elasticloadbalancing:DeleteRule",
                "elasticloadbalancing:DescribeSSLPolicies",
                "ec2:AuthorizeSecurityGroupEgress",
                "elasticloadbalancing:AttachLoadBalancerToSubnets",
                "ec2:TerminateInstances",
                "iam:GetInstanceProfile",
                "elasticloadbalancing:DescribeTags",
                "ec2:DescribeTags",
                "ec2:DeleteRoute",
                "ec2:DescribeLaunchTemplateVersions",
                "elasticloadbalancing:*",
                "iam:ListInstanceProfiles",
                "elasticloadbalancing:CreateLoadBalancerListeners",
                "ec2:CreateLaunchTemplateVersion",
                "iam:CreateOpenIDConnectProvider",
                "ec2:DescribeHosts",
                "ec2:DescribeImages",
                "kms:ListKeys",
                "iam:ListPolicyVersions",
                "iam:ListOpenIDConnectProviders",
                "ec2:DeleteSecurityGroup",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:SetSecurityGroups",
                "iam:ListUsers",
                "ec2:ModifyLaunchTemplate",
                "ec2:AttachNetworkInterface",
                "iam:DeletePolicyVersion",
                "ecr:GetRepositoryPolicy",
                "elasticloadbalancing:ModifyTargetGroup",
                "iam:ListUserTags",
                "wafv2:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:ssm:*:108643707544:parameter/aws/*",
                "arn:aws:ssm:*::parameter/aws/*"
            ]
        }
    ]
})
tags = {
       Name="${var.client_name}-${var.environment}-${var.region_name}-eks-automation-policy2"
       Owner = "WFL-DEVops"
  }
}

resource "aws_iam_role_policy_attachment" "test-attach-xor-eks-automation" {
  role       = aws_iam_role.test_role.name
  policy_arn = aws_iam_policy.xor-eks-automation.arn
}

resource "aws_iam_instance_profile" "test_profile" {
  name  = "${var.client_name}-${var.environment}-${var.region_name}-profile1"
  role =  aws_iam_role.test_role.name
}
