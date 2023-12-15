import aws_cdk as core
import aws_cdk.assertions as assertions

from cdk_centroservicio_local.cdk_centroservicio_local_stack import CdkCentroservicioLocalStack

# example tests. To run these tests, uncomment this file along with the example
# resource in cdk_centroservicio_local/cdk_centroservicio_local_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = CdkCentroservicioLocalStack(app, "cdk-centroservicio-local")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
