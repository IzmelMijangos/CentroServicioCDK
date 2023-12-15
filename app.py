#!/usr/bin/env python3
import os

import aws_cdk as cdk

from cdk_centroservicio_local.cdk_centroservicio_local_stack import CdkCentroservicioLocalStack


app = cdk.App()
CdkCentroservicioLocalStack(app, "Centroservicio",
    env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')),
    )

app.synth()
