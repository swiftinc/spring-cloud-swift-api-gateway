from diagrams import Diagram, Cluster, Edge
from diagrams.onprem.network import Kong
from diagrams.onprem.compute import Server
from diagrams.onprem.client import User, Client
from diagrams.oci.security import CloudGuard
from diagrams import Diagram

with Diagram("Spring Cloud Swift API Gateway", show=False, outformat="png", graph_attr={
    "pad": "1.0"
}):
    swift_api_gateway = CloudGuard("Swift")
    with Cluster("On premises", graph_attr={"margin": "25"}):
        kong = Kong("Kong APIGW")
        spring_cloud = Server("Spring Cloud Gateway")
        kong >> Edge(label="2") >> spring_cloud >> Edge(
            label="3") >> swift_api_gateway
    with Cluster("Clients", graph_attr={"bgcolor": "#EBF3E7"}):
        bnkabebb = Client("BNKABEBB")
        bnkbbebb = Client("BNKBBEBB")
        bnkabebb >> Edge(label="1") >> kong
    User("Test") >> Edge(style="dashed",
                         label="Direct access for testing") >> spring_cloud
