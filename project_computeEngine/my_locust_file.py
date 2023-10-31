from locust import HttpUser, task, between, events, constant
import time

class MyUser(HttpUser):
    wait_time = constant(10)

    @task
    def test_propose_1(self):
        
        response_test_propose = self.client.post('/propose_credential/')

        #response_test_propose = self.client.post('/accept_connection/')

        