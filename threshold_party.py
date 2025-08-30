"""
Threshold Blind Signing Party Command
Implements T-out-of-N threshold blind signing with JSON-RPC communication.
"""

import argparse
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import traceback
import requests
import sys
from ploversign_api import plover_128_1
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor

class JSONRPCHandler:
    """Handle JSON-RPC 2.0 requests and responses."""
    
    @staticmethod
    def create_request(method, params, request_id=None):
        if request_id is None:
            request_id = str(uuid.uuid4())
        return {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }
    
    @staticmethod
    def create_response(result, request_id):
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id
        }
    
    @staticmethod
    def create_error(error_code, message, request_id=None):
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": error_code,
                "message": message
            },
            "id": request_id
        }

class ThresholdParty:
    def __init__(self, party_id, party_type, threshold=None, total_parties=None, user_port=8000, signer_hosts=None, runs=1):
        self.party_id = party_id
        self.party_type = party_type  # "user" or "signer"
        self.threshold = threshold
        self.total_parties = total_parties
        self.user_port = user_port
        self.signer_hosts = signer_hosts or {}  # Dict mapping signer_id -> (host, port)
        self.runs = runs
        self.plover = plover_128_1
        
        # State
        self.connected_parties = set()
        self.sk = None
        self.vk = None
        self.message = None
        
        # Protocol state
        self.st_u = None
        self.commitments = {}
        self.witness_values = {}
        self.final_responses = {}

    @property
    def signer_list(self):
        """Get sorted list of connected signer IDs."""
        return sorted(list(self.connected_parties))

    def encode_to_base64(self, data):
        """Encode bytes to base64 string for JSON transport."""
        if isinstance(data, bytes):
            return base64.b64encode(data).decode('utf-8')
        elif isinstance(data, list):
            return [self.encode_to_base64(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self.encode_to_base64(item) for item in data)
        return data

    def decode_from_base64(self, data):
        """Decode base64 string to bytes from JSON transport."""
        if isinstance(data, str):
            try:
                return base64.b64decode(data.encode('utf-8'))
            except:
                return data
        elif isinstance(data, list):
            return [self.decode_from_base64(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self.decode_from_base64(item) for item in data)
        return data

class UserParty(ThresholdParty):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message = b"Hello, threshold world!"
        
    def run(self):
        print(f"Starting user party, connecting to {self.threshold} signers...")
        print(f"Will perform {self.runs} signing run(s) for measurement averaging")
        
        # Connect to signers
        self.connect_to_signers()
        
        # Perform keygen once
        self.perform_keygen()
        
        # Track measurements across runs
        round1_times = []
        round2_times = []
        round3_times = []
        total_times = []
        successful_runs = 0
        
        print(f"\n{'='*50}")
        print(f"Starting {self.runs} signing protocol run(s)...")
        print(f"{'='*50}")
        
        for run_num in range(1, self.runs + 1):
            print(f"\n--- Run {run_num}/{self.runs} ---")
            
            try:
                round1_time, round2_time, round3_time = self.start_signing_protocol()
                run_total_time = round1_time + round2_time + round3_time
                
                round1_times.append(round1_time)
                round2_times.append(round2_time)
                round3_times.append(round3_time)
                total_times.append(run_total_time)
                successful_runs += 1
                
                print(f"Run {run_num} completed successfully in {run_total_time:.3f} seconds")
                
            except Exception as e:
                print(f"Run {run_num} failed: {e}")
                traceback.print_exc()
                continue
        
        # Print averaged results
        if successful_runs > 0:
            print(f"\n{'='*50}")
            print(f"PERFORMANCE SUMMARY ({successful_runs}/{self.runs} successful runs)")
            print(f"{'='*50}")
            
            if successful_runs > 1:
                print(f"Round 1 (Commitments): {sum(round1_times)/len(round1_times):.3f}s ± {self._std_dev(round1_times):.3f}s")
                print(f"Round 2 (Witnesses):   {sum(round2_times)/len(round2_times):.3f}s ± {self._std_dev(round2_times):.3f}s")
                print(f"Round 3 (Responses):   {sum(round3_times)/len(round3_times):.3f}s ± {self._std_dev(round3_times):.3f}s")
                print(f"Total Protocol Time:   {sum(total_times)/len(total_times):.3f}s ± {self._std_dev(total_times):.3f}s")
            else:
                print(f"Round 1 (Commitments): {round1_times[0]:.3f}s")
                print(f"Round 2 (Witnesses):   {round2_times[0]:.3f}s")
                print(f"Round 3 (Responses):   {round3_times[0]:.3f}s")
                print(f"Total Protocol Time:   {total_times[0]:.3f}s")
                
            print(f"Success Rate: {successful_runs}/{self.runs} ({100*successful_runs/self.runs:.1f}%)")
        else:
            print(f"\nAll {self.runs} runs failed!")
            
    def _std_dev(self, values):
        """Calculate standard deviation of a list of values."""
        if len(values) <= 1:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
    
    def connect_to_signers(self):
        print("Discovering and connecting to signers...")
        signer_ids = list(self.signer_hosts.keys())  # Use configured signer IDs
        
        connected = set()
        max_attempts = 30  # Maximum connection attempts
        attempt = 0
        
        while len(connected) < self.threshold and attempt < max_attempts:
            attempt += 1
            print(f"Connection attempt {attempt}...")
            
            # Try to connect to all remaining signers in parallel
            remaining_signers = [sid for sid in signer_ids if sid not in connected]
            
            def try_connect_signer(signer_id):
                try:
                    response = self.ping_signer(signer_id)
                    if response and response.get("result", {}).get("status") == "ready":
                        return signer_id, True
                except Exception as e:
                    host, port = self.signer_hosts[signer_id]
                    print(f"Failed to connect to signer {signer_id} at {host}:{port}: {e}")
                return signer_id, False
            
            # Parallel connection attempts
            with ThreadPoolExecutor(max_workers=len(remaining_signers)) as executor:
                futures = [executor.submit(try_connect_signer, signer_id) for signer_id in remaining_signers]
                for future in futures:
                    signer_id, success = future.result()
                    if success:
                        connected.add(signer_id)
                        host, port = self.signer_hosts[signer_id]
                        print(f"Connected to signer {signer_id} at {host}:{port}. Connected: {len(connected)}/{self.threshold}")
            
            if len(connected) < self.threshold:
                print(f"Waiting for more signers... ({len(connected)}/{self.threshold} connected)")
                time.sleep(1)  # Wait before retrying
        
        if len(connected) < self.threshold:
            raise Exception(f"Could not connect to enough signers. Connected: {len(connected)}/{self.threshold}")
            
        self.connected_parties = connected
        print("All signers connected!")

    def ping_signer(self, signer_id):
        """Ping a signer using JSON-RPC."""
        request = JSONRPCHandler.create_request("ping", {})
        return self.send_rpc_to_signer(signer_id, request)

    def send_rpc_to_signer(self, signer_id, rpc_request):
        """Send JSON-RPC request to a signer."""
        try:
            if signer_id in self.signer_hosts:
                host, port = self.signer_hosts[signer_id]
            else:
                # Fallback to default behavior
                host = "localhost"
                port = 8000 + signer_id
            
            url = f"http://{host}:{port}/"
            response = requests.post(url, json=rpc_request, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"HTTP error {response.status_code} from signer {signer_id} at {host}:{port}")
            return None
        except Exception as e:
            host, port = self.signer_hosts.get(signer_id, ("localhost", 8000 + signer_id))
            print(f"Failed to send RPC to signer {signer_id} at {host}:{port}: {e}")
            return None
    
    def perform_keygen(self):
        print("Performing threshold keygen...")
        self.sk_shares, self.vk = self.plover.keygen(self.threshold, self.total_parties)
        
        # Distribute shares to signers in parallel
        signer_list = self.signer_list
        
        def distribute_share_to_signer(signer_info):
            i, signer_id = signer_info
            share = self.sk_shares[i]
            # Recursively encode the entire share structure
            encoded_share = self.encode_to_base64(share)
            request = JSONRPCHandler.create_request("receive_share", {
                "share": encoded_share,
                "vk": self.encode_to_base64(self.plover.encode_vk(self.vk))
            })
            response = self.send_rpc_to_signer(signer_id, request)
            return signer_id, response is not None
        
        # Parallel share distribution
        with ThreadPoolExecutor(max_workers=len(signer_list)) as executor:
            futures = [executor.submit(distribute_share_to_signer, (i, signer_id)) 
                      for i, signer_id in enumerate(signer_list)]
            
            success_count = 0
            for future in futures:
                signer_id, success = future.result()
                if success:
                    success_count += 1
                    print(f"Distributed key share to signer {signer_id}")
                else:
                    print(f"Failed to distribute key share to signer {signer_id}")
        
        print(f"Distributed key shares to {success_count}/{len(signer_list)} signers")
        
        if success_count < len(signer_list):
            raise Exception(f"Failed to distribute shares to all signers ({success_count}/{len(signer_list)})")
    
    def start_signing_protocol(self):
        time.sleep(0.1)  # Brief pause between runs
        print("Starting signing protocol...")
        
        # Use the threshold signing protocol properly
        vk_b = self.plover.encode_vk(self.vk)
        vk, tr, _ = self.plover.decode_vk(vk_b)
        
        # Phase 1: User init for threshold signing
        self.st_u, pm_u = self.plover.sign_user_init(vk, tr, self.message)
        self.pm_u = pm_u
        
        # Round 1: Collect commitments
        round1_time = self.round1_collect_commitments()
        
        # Round 2: Distribute commitments and collect witnesses
        round2_time = self.round2_distribute_commitments_collect_witnesses()
        
        # Round 3: Distribute witnesses and collect final responses
        round3_time = self.round3_distribute_witnesses_collect_responses()
        
        return round1_time, round2_time, round3_time

    def round1_collect_commitments(self):
        start_time = time.time()
        print("Round 1: Collecting commitments...")
        self.commitments = {}
        
        signer_list = self.signer_list
        
        def send_round1_to_signer(signer_id):
            request = JSONRPCHandler.create_request("round1", {
                "pm_u": self.encode_to_base64(self.pm_u),
                "signer_set": signer_list
            })
            response = self.send_rpc_to_signer(signer_id, request)
            if response and response.get("result", {}).get("commitment"):
                commitment = self.decode_from_base64(response["result"]["commitment"])
                return signer_id, commitment
            return signer_id, None
        
        # Parallelize round 1 calls
        with ThreadPoolExecutor(max_workers=len(signer_list)) as executor:
            futures = [executor.submit(send_round1_to_signer, signer_id) for signer_id in signer_list]
            for future in futures:
                signer_id, commitment = future.result()
                if commitment is not None:
                    self.commitments[signer_id] = commitment
                    print(f"Collected commitment from signer {signer_id}")
        
        round1_time = time.time() - start_time
        print(f"Round 1 completed in {round1_time:.3f} seconds")
        return round1_time
    
    def round2_distribute_commitments_collect_witnesses(self):
        start_time = time.time()
        print("Round 2: Distributing commitments and collecting witnesses...")
        self.witness_values = {}
        
        signer_list = self.signer_list
        commitments_data = {str(k): self.encode_to_base64(v) for k, v in self.commitments.items()}
        
        def send_round2_to_signer(signer_id):
            request = JSONRPCHandler.create_request("round2", {"commitments": commitments_data})
            response = self.send_rpc_to_signer(signer_id, request)
            if response and response.get("result", {}).get("witness"):
                witness = self.decode_from_base64(response["result"]["witness"])
                return signer_id, witness
            return signer_id, None
        
        # Parallelize round 2 calls
        with ThreadPoolExecutor(max_workers=len(signer_list)) as executor:
            futures = [executor.submit(send_round2_to_signer, signer_id) for signer_id in signer_list]
            for future in futures:
                signer_id, witness = future.result()
                if witness is not None:
                    self.witness_values[signer_id] = witness
                    print(f"Collected witness from signer {signer_id}")
        
        round2_time = time.time() - start_time
        print(f"Round 2 completed in {round2_time:.3f} seconds")
        return round2_time
    
    def round3_distribute_witnesses_collect_responses(self):
        start_time = time.time()
        print("Round 3: Distributing witnesses and collecting final responses...")
        
        signer_list = self.signer_list
        witnesses_data = {str(k): self.encode_to_base64(v) for k, v in self.witness_values.items()}
        
        def send_round3_to_signer(signer_id):
            request = JSONRPCHandler.create_request("round3", {
                "witnesses": witnesses_data
            })
            response = self.send_rpc_to_signer(signer_id, request)
            if response and response.get("result", {}).get("final_response"):
                final_resp = response["result"]["final_response"]
                # Decode z2
                final_resp = self.decode_from_base64(final_resp)
                return signer_id, final_resp
            return signer_id, None
        
        # Parallelize round 3 calls
        self.final_responses = {}
        with ThreadPoolExecutor(max_workers=len(signer_list)) as executor:
            futures = [executor.submit(send_round3_to_signer, signer_id) for signer_id in signer_list]
            success_count = 0
            for future in futures:
                signer_id, final_resp = future.result()
                if final_resp is not None:
                    self.final_responses[signer_id] = final_resp
                    print(f"Collected final response from signer {signer_id}")
                    success_count += 1
        
        round3_time = time.time() - start_time
        print(f"Round 3 completed in {round3_time:.3f} seconds ({success_count}/{len(signer_list)} signers)")
        
        self.complete_signing()
        return round3_time

    def complete_signing(self):
        print("Aggregating final responses...")
        
        vk_b = self.plover.encode_vk(self.vk)
        vk, tr, _ = self.plover.decode_vk(vk_b)

        # Aggregate the responses
        witnesses_list = list(self.witness_values.values())
        final_responses_list = list(self.final_responses.values())
        pm_s = self.plover.sign_server_aggregate(witnesses_list, final_responses_list)

        # Complete user signing using threshold API
        sig = self.plover.sign_user_final(tr, self.st_u, pm_s)
        
        # Verify signature using threshold API
        verify_result = self.plover.verify_msg(vk, tr, self.message, sig)
        print(f"Signature verification: {'SUCCESS' if verify_result else 'FAILED'}")
        
        if verify_result:
            print("Threshold blind signing completed successfully!")
            
            # Optionally generate proof (measured separately)
            try:
                proof_start_time = time.time()
                proof = self.plover.prove_signature_existence(vk, tr, self.message, sig)
                proof_verify = self.plover.verify_signature_existence(vk, tr, self.message, proof)
                proof_time = time.time() - proof_start_time
                print(f"Proof verification: {'SUCCESS' if proof_verify else 'FAILED'}")
                print(f"Proof generation+verification time: {proof_time:.3f}s (not included in protocol time)")
            except Exception as e:
                print(f"Proof generation failed: {e}")
        else:
            raise Exception("Signature verification failed")

class SignerRPCHandler(BaseHTTPRequestHandler):
    def __init__(self, party, *args, **kwargs):
        self.party = party
        super().__init__(*args, **kwargs)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            rpc_request = json.loads(post_data.decode('utf-8'))
            response = self.handle_rpc_request(rpc_request)
        except Exception as e:
            response = JSONRPCHandler.create_error(-32700, f"Parse error: {e}")
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_rpc_request(self, request):
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")
        
        try:
            if method == "ping":
                return JSONRPCHandler.create_response({"status": "ready"}, request_id)
                
            elif method == "receive_share":
                # Recursively decode the entire share structure
                self.party.sk = self.party.decode_from_base64(params["share"])
                self.party.vk_b = self.party.decode_from_base64(params["vk"])
                print("Received key share")
                return JSONRPCHandler.create_response({"status": "success"}, request_id)
                
            elif method == "round1":
                pm_u = self.party.decode_from_base64(params["pm_u"])
                signer_set = params["signer_set"]
                
                # Store the received data for threshold signing
                self.party.pm_u = pm_u
                self.party.signer_set = signer_set
                
                # Use threshold signing round 1
                self.party.st_s, commitment = self.party.plover.sign_server1(
                    self.party.sk, pm_u, signer_set
                )
                
                print("Generated commitment")
                return JSONRPCHandler.create_response({
                    "status": "success",
                    "commitment": self.party.encode_to_base64(commitment)
                }, request_id)

            elif method == "round2":
                commitments = {int(k): self.party.decode_from_base64(v) for k, v in params["commitments"].items()}
                commitments_list = [commitments[k] for k in sorted(commitments.keys())]
                
                self.party.st_s, self.party.witness = self.party.plover.sign_server2(
                    self.party.sk, self.party.st_s, commitments_list
                )
                
                print("Generated witness")
                return JSONRPCHandler.create_response({
                    "status": "success", 
                    "witness": self.party.encode_to_base64(self.party.witness)
                }, request_id)
                
            elif method == "round3":
                witnesses = {int(k): self.party.decode_from_base64(v) for k, v in params["witnesses"].items()}
                witnesses_list = [witnesses[k] for k in sorted(witnesses.keys())]
                
                # Use the stored vk_b to get tr
                vk, tr, _ = self.party.plover.decode_vk(self.party.vk_b)
                
                self.party.final_response = self.party.plover.sign_server3(
                    self.party.sk, tr, self.party.st_s, witnesses_list
                )
                
                print("Generated final response")
                return JSONRPCHandler.create_response({
                    "status": "success",
                    "final_response": self.party.encode_to_base64(self.party.final_response),  # z2
                }, request_id)

            else:
                return JSONRPCHandler.create_error(-32601, f"Method not found: {method}", request_id)
                
        except Exception as e:
            return JSONRPCHandler.create_error(-32603, f"Internal error: {e}", request_id)

    def log_message(self, format, *args):
        pass

class SignerParty(ThresholdParty):
    def __init__(self, *args, signer_host="localhost", signer_port=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer_host = signer_host
        self.signer_port = signer_port if signer_port else 8000 + self.party_id
        self.commitment = None
        self.witness = None
        self.final_response = None
        
    def run(self):
        print(f"Starting signer party {self.party_id}")
        
        # Start local server
        handler = lambda *args, **kwargs: SignerRPCHandler(self, *args, **kwargs)
        server = HTTPServer((self.signer_host, self.signer_port), handler)
        
        print(f"Signer {self.party_id} JSON-RPC server listening on {self.signer_host}:{self.signer_port}")
        print("Waiting for user to connect...")
        server.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="Threshold Blind Signing Party")
    parser.add_argument("--party-id", type=int, required=True, help="Party ID (unique integer)")
    parser.add_argument("--party-type", choices=["user", "signer"], required=True, help="Party type")
    parser.add_argument("--threshold", type=int, help="Threshold T (required for user)")
    parser.add_argument("--total-parties", type=int, help="Total parties N (required for user)")
    parser.add_argument("--user-port", type=int, default=8000, help="User port")
    parser.add_argument("--signer-hosts", nargs="*", help="List of signer hosts (e.g., host1:port1 host2:port2). If not specified, uses localhost with ports 8001, 8002, etc.")
    parser.add_argument("--signer-host", default="localhost", help="Host address for this signer party (signer only)")
    parser.add_argument("--signer-port", type=int, help="Port for this signer party (defaults to 8000 + party-id for signer)")
    parser.add_argument("--runs", type=int, default=1, help="Number of signing runs to perform (for averaging measurements)")
    
    args = parser.parse_args()
    
    if args.party_type == "user":
        if args.threshold is None or args.total_parties is None:
            print("Error: --threshold and --total-parties required for user")
            sys.exit(1)
        
        # Parse signer hosts
        signer_hosts = {}
        if args.signer_hosts:
            for i, host_port in enumerate(args.signer_hosts, 1):
                if ':' in host_port:
                    host, port = host_port.split(':')
                    signer_hosts[i] = (host, int(port))
                else:
                    signer_hosts[i] = (host_port, 8000 + i)
        else:
            # Default: use localhost with sequential ports
            for i in range(1, args.threshold + 1):
                signer_hosts[i] = ("localhost", 8000 + i)
        
        party = UserParty(
            args.party_id, args.party_type, args.threshold, args.total_parties,
            args.user_port, signer_hosts, args.runs
        )
    else:
        party = SignerParty(
            args.party_id, args.party_type,
            user_port=args.user_port,
            signer_host=args.signer_host, 
            signer_port=args.signer_port if args.signer_port else 8000 + args.party_id
        )
    
    try:
        party.run()
    except KeyboardInterrupt:
        print("Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()
