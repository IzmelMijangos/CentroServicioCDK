from aws_cdk import (
    Stack, 
    Duration,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
    aws_elasticloadbalancingv2 as elbv2,
    aws_ecs as ecs,
    aws_ecr as ecr,
    aws_codebuild as codebuild,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_ec2 as ec2,
    aws_secretsmanager as sm,
    CfnOutput,
    SecretValue,
    Duration,
    aws_iam as iam,
    aws_s3 as s3,
    aws_codepipeline as codepipeline,
    aws_elasticache as ec,
    aws_codestarconnections as codestarconnections,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as targets,
)

from constructs import Construct

class CdkCentroservicioLocalStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        # Referencia a la SECRET_KEY en Secrets Manager
        secret_key_secret = secretsmanager.Secret.from_secret_name_v2(
            self, 'SecretKeySecret', 'SECRET_KEY_APP_CS'
        ) 

        # Crear una nueva VPC con subredes públicas y privadas y una puerta de enlace de Internet
        vpc = ec2.Vpc(self, "CSVpc",
                      max_azs=2,
                      subnet_configuration=[
                          ec2.SubnetConfiguration(name="Public", subnet_type=ec2.SubnetType.PUBLIC),
                          ec2.SubnetConfiguration(name="Private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                      ],
                      nat_gateways=1
                      )

        # Crear un grupo de seguridad y agregar reglas de entrada para tráfico IPv4 e IPv6
        db_security_group = ec2.SecurityGroup(self, "DatabaseSecurityGroup", vpc=vpc)
        db_security_group.add_ingress_rule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(5432))
        db_security_group.add_ingress_rule(ec2.Peer.ipv6('::/0'), ec2.Port.tcp(5432))

        # Crear un secreto para la contraseña de la base de datos
        db_password = sm.Secret(self, "CSDBPassword",
                                generate_secret_string=sm.SecretStringGenerator(
                                    secret_string_template='{"username": "dbadmin"}',
                                    exclude_characters='{}[]()\'"/\\ @',
                                    generate_string_key='password'
                                )
                                )

        # Crear una instancia de Base de Datos RDS
        db_instance = rds.DatabaseInstance(
            self, "CSDatabase",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_12
            ),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
            ),
            vpc=vpc,
            vpc_subnets={
                "subnet_type": ec2.SubnetType.PUBLIC
            },
            credentials=rds.Credentials.from_secret(db_password),
            security_groups=[db_security_group],
            multi_az=False,
            allocated_storage=20,
            max_allocated_storage=100,
            allow_major_version_upgrade=False,
            auto_minor_version_upgrade=True,
            delete_automated_backups=True,
            deletion_protection=False,
            publicly_accessible=True,
            storage_encrypted=False,
            storage_type=rds.StorageType.GP2,
            backup_retention=Duration.days(7),
            enable_performance_insights=True,
            performance_insight_retention=rds.PerformanceInsightRetention.DEFAULT,
            parameter_group=rds.ParameterGroup.from_parameter_group_name(
                self, "ParameterGroup",
                parameter_group_name="default.postgres12"
            ),
        )
        db_instance_arn = db_instance.instance_arn

        # Crea el repositorio en ECR
        ecr_repository = ecr.Repository(self, "CSEcrRepository")   

        # Fuente del artefacto para el código fuente
        source_output = codepipeline.Artifact()

        # Definir un artefacto de salida para la imagen construida
        build_output = codepipeline.Artifact()

        # Define un recurso de AWS CodeStar Connections y obtiene el ARN
        codestar_connection = codestarconnections.CfnConnection(
            self, "MyCodeStarConnection",
            connection_name="MyConnection",
            provider_type="GitHub",
        )
        connection_arn = codestar_connection.attr_connection_arn
        
        # Define un rol de IAM para CodeBuild con permisos para interactuar con ECR y crear un proyecto de CodeBuild para construir y subir la imagen Docker
        codebuild_role = iam.Role(self, "CodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryPowerUser"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess")  # Agrega esta línea
            ]
        )

        # Agregar permisos para acceder a Secrets Manager
        codebuild_role.add_to_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=["arn:aws:secretsmanager:us-east-1:888569750886:secret:DockerHub-YucYJV",],  # Asegúrate de usar el ARN correcto del secreto
        ))
        
        build_project = codebuild.PipelineProject(self, "BuildProject",
            build_spec=codebuild.BuildSpec.from_object({
                'version': '0.2',
                'phases': {
                    'pre_build': {
                        'commands': [
                            'echo Logging in to Amazon ECR...',
                            '$(aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email)',
                        ]
                    },
                    'build': {
                        'commands': [
                            'echo Build started on `date`',
                            'echo Building the Docker image...',
                            'docker build -t $REPOSITORY_URI:backend -f Dockerfile.back.prod .',
                        ]
                    },
                    'post_build': {
                        'commands': [
                            'echo Build completed on `date`',
                            'echo Pushing the Docker image...',
                            'docker push $REPOSITORY_URI:backend',
                            'echo Writing image definitions file...',
                            'printf \'[{"name":"CSEcrRepository","imageUri":"%s"}]\' $REPOSITORY_URI:backend > imagedefinitions.json',
                        ]
                    }
                },
                'artifacts': {
                    'files': ['imagedefinitions.json']
                },
                'environment': {
                    'privileged-mode': True,
                    'buildImage': codebuild.LinuxBuildImage.STANDARD_5_0,
                },
            }),
            environment_variables={
                'REPOSITORY_URI': codebuild.BuildEnvironmentVariable(value=ecr_repository.repository_uri),
            },
            role=codebuild_role,
        )
        # Asignar permiso al proyecto CodeBuild para interactuar con ECR
        ecr_repository.grant_pull_push(build_project)
        codebuild_role.add_to_policy(iam.PolicyStatement(
            actions=["ecs:UpdateService"],
            resources=["*"]
        ))

        # Crear un rol de IAM para el proyecto CodeBuild de verificación de migraciones y agrega todas las acciones y recursos necesarios
        codebuild_migration_role = iam.Role(self, "CodeBuildMigrationRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("SecretsManagerReadWrite"),
            ],
        )

        # Para acciones relacionadas con RDS
        codebuild_migration_role.add_to_policy(iam.PolicyStatement(
            actions=["rds-db:connect"],
            resources=[db_instance_arn],
        ))

        # Para acciones relacionadas con EC2
        codebuild_migration_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "ec2:DescribeNetworkInterfaces",
                "ec2:DeleteNetworkInterface"
            ],
            resources=["*"],
        ))

        # Para acciones relacionadas con ECR
        codebuild_migration_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "ecr:GetAuthorizationToken",
            ],
            resources=["*"],
        ))

        codebuild_migration_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer"
            ],
            resources=[ecr_repository.repository_arn],
        ))

        # Agregar permisos para acceder a Secrets Manager
        codebuild_migration_role.add_to_policy(iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=["*"],
        ))
        
        # Crear un proyecto de CodeBuild para la ejecución de migraciones
        migrations_project = codebuild.PipelineProject(self, "MigrationsProject",
            build_spec=codebuild.BuildSpec.from_object({
                'version': '0.2',
                'phases': {
                    'pre_build': {
                        'commands': [
                            'echo Logging in to Amazon ECR...',
                            '$(aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email)',
                        ]
                    },
                    'build': {
                        'commands': [
                            'echo Running migrations...',
                            'docker run '
                            '-e DATABASE_NAME=$DATABASE_NAME '
                            '-e DATABASE_USER=$DATABASE_USER '
                            '-e DATABASE_PASSWORD=$DATABASE_PASSWORD '
                            '-e DATABASE_HOST=$DATABASE_HOST '
                            '-e DATABASE_PORT=$DATABASE_PORT '
                            '$REPOSITORY_URI:backend python manage.py migrate',
                        ]
                    }
                },
                'environment': {
                    'buildImage': codebuild.LinuxBuildImage.from_docker_registry(f"{ecr_repository.repository_uri}:backend"),
                    'privileged-mode': True,
                },
            }),
            environment_variables={
                'REPOSITORY_URI': codebuild.BuildEnvironmentVariable(value=ecr_repository.repository_uri), 
                'DATABASE_NAME': codebuild.BuildEnvironmentVariable(
                    value=f'{db_password.secret_arn}:engine',
                    type=codebuild.BuildEnvironmentVariableType.SECRETS_MANAGER
                ),
                'DATABASE_USER': codebuild.BuildEnvironmentVariable(
                    value=f'{db_password.secret_arn}:username',
                    type=codebuild.BuildEnvironmentVariableType.SECRETS_MANAGER
                ),
                'DATABASE_PASSWORD': codebuild.BuildEnvironmentVariable(
                    value=f'{db_password.secret_arn}:password',
                    type=codebuild.BuildEnvironmentVariableType.SECRETS_MANAGER
                ),
                'DATABASE_HOST': codebuild.BuildEnvironmentVariable(
                    value=f'{db_password.secret_arn}:host',
                    type=codebuild.BuildEnvironmentVariableType.SECRETS_MANAGER
                ),
                'DATABASE_PORT': codebuild.BuildEnvironmentVariable(
                    value=f'{db_password.secret_arn}:port',
                    type=codebuild.BuildEnvironmentVariableType.SECRETS_MANAGER
                ),
            },
            role=codebuild_migration_role,
        )

        # Pipeline de CodePipeline
        pipeline = codepipeline.Pipeline(self, "CSPipeline",
            stages=[
                codepipeline.StageProps(
                    stage_name='Source',
                    actions=[
                        codepipeline_actions.CodeStarConnectionsSourceAction(
                            action_name="GitHub_Source",
                            owner="IzmelMijangos",
                            repo="CentroServicioBackend",
                            branch="master",
                            connection_arn=connection_arn,
                            output=source_output,
                            ),
                        ]
                ),
                codepipeline.StageProps(
                    stage_name='Build',
                    actions=[
                        codepipeline_actions.CodeBuildAction(
                            action_name='Build',
                            project=build_project,
                            input=source_output,
                            outputs=[build_output],
                        ),
                    ]
                ),
                codepipeline.StageProps(
                    stage_name='CheckMigrations',
                    actions=[
                        codepipeline_actions.CodeBuildAction(
                            action_name='CheckMigrations',
                            project=migrations_project,
                            input=source_output,  # Utiliza el mismo output de la etapa 'Source'
                            # No necesitas un output si solo estás verificando algo
                        )
                    ]
                ),
                codepipeline.StageProps(
                    stage_name='Mock',
                    actions=[
                        codepipeline_actions.ManualApprovalAction(
                            action_name='Manual_Approval',
                            run_order=1
                        )
                    ]
                ),
            ],
        )

        # Crea un Cluster en ECS
        ecs_cluster = ecs.Cluster(self, "CSCluster", vpc=vpc)

        #Definir un Application Load Balancer
        alb = elbv2.ApplicationLoadBalancer(
            self, 'MyALB',
            vpc=vpc,
            internet_facing=True,  # 'True' para acceso público, 'False' para interno
            load_balancer_name='MyApplicationLoadBalancer'
        )

        # Crear un Grupo de Seguridad para el ALB
        alb_security_group = ec2.SecurityGroup(
            self, 'ALBSecurityGroup',
            vpc=vpc,
            description='Allow http access to alb',
            allow_all_outbound=True
        )
        alb_security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
            'Allow HTTP traffic from anywhere'
        )

        alb.add_security_group(alb_security_group)

        # Añadir capacidad de EC2 al clúster de ECS
        ecs_cluster.add_capacity(
            "CSClusterCapacity",
            instance_type=ec2.InstanceType("t2.micro"),
            desired_capacity=1
        )
        
        # Crear una definición de tarea con el contenedor y las variables de entorno
        task_definition = ecs.Ec2TaskDefinition(self, 'TaskDef')
        
        container = task_definition.add_container('backend',
            image=ecs.ContainerImage.from_ecr_repository(ecr_repository, 'backend'), 
            memory_limit_mib=256,
            environment={  
               
            },
            secrets={
                'SECRET_KEY': ecs.Secret.from_secrets_manager(secret_key_secret),
                'NAME': ecs.Secret.from_secrets_manager(db_password, field='engine'),
                'USER': ecs.Secret.from_secrets_manager(db_password, field='username'),
                'PASSWORD': ecs.Secret.from_secrets_manager(db_password, field='password'),
                'HOST': ecs.Secret.from_secrets_manager(db_password, field='host'),
                'PORT': ecs.Secret.from_secrets_manager(db_password, field='port'),
            },
        )

        # Añade el mapeo de puertos si es necesario
        container.add_port_mappings(ecs.PortMapping(container_port=8080, host_port=8080))

        # Crear un Grupo de Objetivos para el Listener
        target_group = elbv2.ApplicationTargetGroup(
            self, 'TargetGroup',
            vpc=vpc,
            port=80,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(
                path='/healthcheck'  # Asegúrate de que este endpoint existe en tu aplicación
            )
        )

#-------Dar Permisos a GITHUB EN PIPELINE---------------------------------------------------------#
    
        # Crear un Servicio de ECS que use el ALB
        ecs_service = ecs.Ec2Service(
            self, "CSService",
            cluster=ecs_cluster,
            task_definition=task_definition,
            service_name='MyECSService'
        )


#---------------------------Se tiene que eliminar la tarea previamente creada-------------------------------------#

        # # Definir un Listener
        # listener = alb.add_listener('Listener', port=80)      
        # # Añadir el servicio ECS como un objetivo del Listener
        # listener.add_targets(
        #     'ECSTarget',
        #     port=80,
        #     targets=[ecs_service.load_balancer_target(
        #         container_name='backend',
        #         container_port=8080
        #     )]
        # )   

# # # #--------------------------------------------------------------------------------------------------------#


        
        # # Crear una nueva VPC con subredes públicas y privadas y una puerta de enlace de Internet
        # vpc = ec2.Vpc(self, "CSVpc",
        #               max_azs=2,
        #               subnet_configuration=[
        #                   ec2.SubnetConfiguration(name="Public", subnet_type=ec2.SubnetType.PUBLIC),
        #                   ec2.SubnetConfiguration(name="Private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        #               ],
        #               nat_gateways=1
        #               )
        
        # # Crear un grupo de seguridad y agregar reglas de entrada para tráfico IPv4 e IPv6
        # db_security_group = ec2.SecurityGroup(self, "DatabaseSecurityGroup", vpc=vpc)
        # db_security_group.add_ingress_rule(ec2.Peer.ipv4('0.0.0.0/0'), ec2.Port.tcp(5432))
        # db_security_group.add_ingress_rule(ec2.Peer.ipv6('::/0'), ec2.Port.tcp(5432))

        # # Referencia a la SECRET_KEY en Secrets Manager
        # secret_key_secret = secretsmanager.Secret.from_secret_name_v2(
        #     self, 'SecretKeySecret', 'SECRET_KEY_APP_CS'
        # ) 

        # # Crea el repositorio en ECR
        # ecr_repository = ecr.Repository(self, "CSEcrRepository")   

        # # Crear un secreto para la contraseña de la base de datos
        # db_password = sm.Secret(self, "CSDBPassword",
        #                         generate_secret_string=sm.SecretStringGenerator(
        #                             secret_string_template='{"username": "dbadmin"}',
        #                             exclude_characters='{}[]()\'"/\\ @',
        #                             generate_string_key='password'
        #                         )
        #                         )

        # # Crear una instancia de Base de Datos RDS
        # db_instance = rds.DatabaseInstance(
        #     self, "CSDatabase",
        #     engine=rds.DatabaseInstanceEngine.postgres(
        #         version=rds.PostgresEngineVersion.VER_12
        #     ),
        #     instance_type=ec2.InstanceType.of(
        #         ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        #     ),
        #     vpc=vpc,
        #     vpc_subnets={
        #         "subnet_type": ec2.SubnetType.PUBLIC
        #     },
        #     credentials=rds.Credentials.from_secret(db_password),
        #     security_groups=[db_security_group],
        #     multi_az=False,
        #     allocated_storage=20,
        #     max_allocated_storage=100,
        #     allow_major_version_upgrade=False,
        #     auto_minor_version_upgrade=True,
        #     delete_automated_backups=True,
        #     deletion_protection=False,
        #     publicly_accessible=True,
        #     storage_encrypted=False,
        #     storage_type=rds.StorageType.GP2,
        #     backup_retention=Duration.days(7),
        #     enable_performance_insights=True,
        #     performance_insight_retention=rds.PerformanceInsightRetention.DEFAULT,
        #     parameter_group=rds.ParameterGroup.from_parameter_group_name(
        #         self, "ParameterGroup",
        #         parameter_group_name="default.postgres12"
        #     ),
        # )
        # db_instance_arn = db_instance.instance_arn

        # # Crea un Cluster en ECS
        # ecs_cluster = ecs.Cluster(self, "CSCluster", vpc=vpc)

        # # Añadir capacidad de EC2 al clúster de ECS
        # ecs_cluster.add_capacity(
        #     "CSClusterCapacity",
        #     instance_type=ec2.InstanceType("t2.micro"),
        #     desired_capacity=1
        # )

        # #Definir un Application Load Balancer
        # alb = elbv2.ApplicationLoadBalancer(
        #     self, 'MyALB',
        #     vpc=vpc,
        #     internet_facing=True,  # 'True' para acceso público, 'False' para interno
        #     load_balancer_name='MyApplicationLoadBalancer'
        # )

        # # Crear un Grupo de Seguridad para el ALB
        # alb_security_group = ec2.SecurityGroup(
        #     self, 'ALBSecurityGroup',
        #     vpc=vpc,
        #     description='Allow http access to alb',
        #     allow_all_outbound=True
        # )
        # alb_security_group.add_ingress_rule(
        #     ec2.Peer.any_ipv4(),
        #     ec2.Port.tcp(80),
        #     'Allow HTTP traffic from anywhere'
        # )
        # alb.add_security_group(alb_security_group)
        
        # # Crear una definición de tarea con el contenedor y las variables de entorno
        # task_definition = ecs.Ec2TaskDefinition(self, 'TaskDef')
        
        # container = task_definition.add_container('backend',
        #     image=ecs.ContainerImage.from_ecr_repository(ecr_repository, 'backend'), 
        #     memory_limit_mib=256,
        #     environment={  
               
        #     },
        #     secrets={
        #         'SECRET_KEY': ecs.Secret.from_secrets_manager(secret_key_secret),
        #         'NAME': ecs.Secret.from_secrets_manager(db_password, field='engine'),
        #         'USER': ecs.Secret.from_secrets_manager(db_password, field='username'),
        #         'PASSWORD': ecs.Secret.from_secrets_manager(db_password, field='password'),
        #         'HOST': ecs.Secret.from_secrets_manager(db_password, field='host'),
        #         'PORT': ecs.Secret.from_secrets_manager(db_password, field='port'),
        #     },
        # )
        # container.add_port_mappings(ecs.PortMapping(container_port=8080, host_port=8080))

        # # Crear un Grupo de Objetivos para el Listener
        # target_group = elbv2.ApplicationTargetGroup(
        #     self, 'TargetGroup',
        #     vpc=vpc,
        #     port=80,
        #     target_type=elbv2.TargetType.IP,
        #     health_check=elbv2.HealthCheck(
        #         path='/healthcheck'  # Asegúrate de que este endpoint existe en tu aplicación
        #     )
        # )

        # # Crear un Servicio de ECS que use el ALB
        # ecs_service = ecs.Ec2Service(
        #     self, "CSService",
        #     cluster=ecs_cluster,
        #     task_definition=task_definition,
        #     service_name='MyECSService'
        # )

        # # Fuente del artefacto para el código fuente
        # source_output = codepipeline.Artifact()

        # # Definir un artefacto de salida para la imagen construida
        # build_output = codepipeline.Artifact()

        # # Definir un artefacto para la definición de la tarea actualizada
        # updated_task_def_output = codepipeline.Artifact()

        # # Define un recurso de AWS CodeStar Connections y obtiene el ARN
        # codestar_connection = codestarconnections.CfnConnection(
        #     self, "MyCodeStarConnection",
        #     connection_name="MyConnection",
        #     provider_type="GitHub",
        # )
        # connection_arn = codestar_connection.attr_connection_arn
        
        # # Define un rol de IAM para CodeBuild con permisos para interactuar con ECR y crear un proyecto de CodeBuild para construir y subir la imagen Docker
        # codebuild_role = iam.Role(self, "CodeBuildRole",
        #     assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
        #     managed_policies=[
        #         iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryPowerUser"),
        #         iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess")  # Agrega esta línea
        #     ]
        # )

        # build_project = codebuild.PipelineProject(self, "BuildProject",
        #     build_spec=codebuild.BuildSpec.from_object({
        #         'version': '0.2',
        #         'phases': {
        #             'pre_build': {
        #                 'commands': [
        #                     'echo Logging in to Amazon ECR...',
        #                     '$(aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email)',
        #                 ]
        #             },
        #             'build': {
        #                 'commands': [
        #                     'echo Build started on `date`',
        #                     'echo Building the Docker image...',
        #                     'docker build -t $REPOSITORY_URI:backend -f Dockerfile.back.prod .',
                            
        #                 ]
        #             },
        #             'post_build': {
        #                 'commands': [
        #                     'echo Build completed on `date`',
        #                     'echo Pushing the Docker image...',
        #                     'docker push $REPOSITORY_URI:backend',
        #                     'echo Writing image definitions file...',
        #                     'printf \'[{"name":"CSEcrRepository","imageUri":"%s"}]\' $REPOSITORY_URI:backend > imagedefinitions.json',
        #                     'aws ecs update-service --cluster $ECS_CLUSTER_NAME --service $ECS_SERVICE_NAME --force-new-deployment'
        #                 ]
        #             }
        #         },
        #         'artifacts': {
        #             'files': ['imagedefinitions.json']
        #         },
        #         'environment': {
        #             'privileged-mode': True,
        #             'buildImage': codebuild.LinuxBuildImage.STANDARD_5_0,
        #         },
        #     }),
        #     environment_variables={
        #         'REPOSITORY_URI': codebuild.BuildEnvironmentVariable(value=ecr_repository.repository_uri),
        #         'ECS_CLUSTER_NAME': codebuild.BuildEnvironmentVariable(value=ecs_cluster.cluster_name),
        #         'ECS_SERVICE_NAME': codebuild.BuildEnvironmentVariable(value=ecs_service.service_name)
        #     },
        #     role=codebuild_role,
        # )
        # # Asigna los permisos necesarios al proyecto de CodeBuild
        # ecr_repository.grant_pull_push(build_project)
        # codebuild_role.add_to_policy(iam.PolicyStatement(
        #     actions=["ecs:UpdateService"],
        #     resources=["*"]  # Especifica aquí tus recursos ECS si es necesario
        # ))

        # # Crear un rol de IAM para el proyecto CodeBuild de verificación de migraciones y agrega todas las acciones y recursos necesarios
        # codebuild_migration_role = iam.Role(self, "CodeBuildMigrationRole",
        #     assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
        #     managed_policies=[
        #         iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess"),
        #         iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsFullAccess"),
        #     ],
        # )

        # # Para acciones relacionadas con RDS
        # codebuild_migration_role.add_to_policy(iam.PolicyStatement(
        #     actions=["rds-db:connect"],
        #     resources=[db_instance_arn],
        # ))

        # # Para acciones relacionadas con EC2
        # codebuild_migration_role.add_to_policy(iam.PolicyStatement(
        #     actions=[
        #         "ec2:DescribeNetworkInterfaces",
        #         "ec2:DeleteNetworkInterface"
        #     ],
        #     resources=["*"],
        # ))

        # # Para acciones relacionadas con ECR
        # codebuild_migration_role.add_to_policy(iam.PolicyStatement(
        #     actions=[
        #         "ecr:GetAuthorizationToken",
        #     ],
        #     resources=["*"],
        # ))

        # codebuild_migration_role.add_to_policy(iam.PolicyStatement(
        #     actions=[
        #         "ecr:BatchGetImage",
        #         "ecr:GetDownloadUrlForLayer"
        #     ],
        #     resources=[ecr_repository.repository_arn],
        # ))
        
        # # Crear un proyecto de CodeBuild para la ejecución de migraciones
        # migrations_project = codebuild.PipelineProject(self, "MigrationsProject",
        #     build_spec=codebuild.BuildSpec.from_object({
        #         'version': '0.2',
        #         'phases': {
        #             'pre_build': {
        #                 'commands': [
        #                     'echo Logging in to Amazon ECR...',
        #                     '$(aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email)',
        #                 ]
        #             },
        #             'build': {
        #                 'commands': [
        #                     'echo Running migrations...',
        #                     'docker run $REPOSITORY_URI:backend python manage.py migrate',
        #                 ]
        #             }
        #         },
        #         'environment': {
        #             'buildImage': codebuild.LinuxBuildImage.from_docker_registry(f"{ecr_repository.repository_uri}:backend"),
        #             'privileged-mode': True,
        #         },
        #     }),

        #     environment_variables={
        #         'REPOSITORY_URI': codebuild.BuildEnvironmentVariable(value=ecr_repository.repository_uri),
        #     },
        #     role=codebuild_migration_role,
        # )

        # # Pipeline de CodePipeline
        # pipeline = codepipeline.Pipeline(self, "CSPipeline",
        #     stages=[
        #         codepipeline.StageProps(
        #             stage_name='Source',
        #             actions=[
        #                 codepipeline_actions.CodeStarConnectionsSourceAction(
        #                     action_name="GitHub_Source",
        #                     owner="IzmelMijangos",
        #                     repo="CentroServicioBackend",
        #                     branch="master",
        #                     connection_arn=connection_arn,
        #                     output=source_output,
        #                     ),
        #                 ]
        #         ),
        #         codepipeline.StageProps(
        #             stage_name='Build',
        #             actions=[
        #                 codepipeline_actions.CodeBuildAction(
        #                     action_name='Build',
        #                     project=build_project,
        #                     input=source_output,
        #                     outputs=[build_output],
        #                 ),
        #             ]
        #         ),
        #         codepipeline.StageProps(
        #             stage_name='CheckMigrations',
        #             actions=[
        #                 codepipeline_actions.CodeBuildAction(
        #                     action_name='CheckMigrations',
        #                     project=migrations_project,
        #                     input=source_output, 
        #                 )
        #             ]
        #         ),
        #         codepipeline.StageProps(
        #             stage_name='Mock',
        #             actions=[
        #                 codepipeline_actions.ManualApprovalAction(
        #                     action_name='Manual_Approval',
        #                     run_order=1
        #                 )
        #             ]
        #         ),
        #     ],
        # )

       
          
        
        # ## cloudwatch_events_role = iam.Role(self, "CloudWatchEventsRole",
        # ##     assumed_by=iam.ServicePrincipal("events.amazonaws.com"),
        # ##     inline_policies={
        # ##         'CloudWatchEventsCodePipelinePolicy': iam.PolicyDocument(
        # ##             statements=[
        # ##                 iam.PolicyStatement(
        # ##                     actions=["codepipeline:StartPipelineExecution"],
        # ##                     resources=[pipeline.pipeline_arn]
        # ##                 )
        # ##             ]
        # ##         )
        # ##     }
        # ## )