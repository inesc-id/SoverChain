from locust import HttpUser, task, between, events, constant
import time

# locust -f my_locust_file.py

class MyUser(HttpUser):
    wait_time = constant(10)

    @task
    def test_propose_1(self):
        
        response_test_propose = self.client.post('/propose_credential/')


        