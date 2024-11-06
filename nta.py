from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
import joblib
import os

#print(os.getcwd())

flow_data = []

flows = {}

def packet_callback(packet):
    global flow_data, flows

    if IP in packet:
        if TCP in packet or UDP in packet:
            flow_key = (
                packet[IP].src,
                packet.sport if TCP in packet or UDP in packet else None,
                packet[IP].dst,
                packet.dport if TCP in packet or UDP in packet else None,
                packet[IP].proto
            )
            current_time = packet.time

            if flow_key not in flows:
                flows[flow_key] = {
                    'total_fwd_packets': 0,
                    'total_bwd_packets': 0,
                    'total_fwd_length': 0,
                    'total_bwd_length': 0,
                    'fwd_packet_lengths': [],
                    'bwd_packet_lengths': [],
                    'timestamps': [],
                    'fwd_iat': [],
                    'bwd_iat': [],
                    'syn_flag_count': 0,
                    'psh_flag_count': 0,
                    'ack_flag_count': 0,
                    'fin_flag_count': 0,
                    'init_win_bytes_forward': None,
                    'init_win_bytes_backward': None,
                }

            flow = flows[flow_key]
            flow['timestamps'].append(current_time)

            if packet[IP].src == flow_key[0]:
                # Forward packet
                flow['total_fwd_packets'] += 1
                flow['total_fwd_length'] += len(packet)
                flow['fwd_packet_lengths'].append(len(packet))
                if TCP in packet:
                    if packet[TCP].flags & 0x02:  # SYN flag
                        flow['syn_flag_count'] += 1
                    if packet[TCP].flags & 0x08:  # PSH flag
                        flow['psh_flag_count'] += 1
                    if packet[TCP].flags & 0x10:  # ACK flag
                        flow['ack_flag_count'] += 1
                    if packet[TCP].flags & 0x01:  # FIN flag
                        flow['fin_flag_count'] += 1
                    if flow['init_win_bytes_forward'] is None:
                        flow['init_win_bytes_forward'] = packet[TCP].window
            else:
                flow['total_bwd_packets'] += 1
                flow['total_bwd_length'] += len(packet)
                flow['bwd_packet_lengths'].append(len(packet))
                if TCP in packet and flow['init_win_bytes_backward'] is None:
                    flow['init_win_bytes_backward'] = packet[TCP].window

            if len(flow['timestamps']) > 1:
                iat = flow['timestamps'][-1] - flow['timestamps'][-2]
                if packet[IP].src == flow_key[0]:
                    flow['fwd_iat'].append(iat)
                else:
                    flow['bwd_iat'].append(iat)
        else:
            print("Packet does not have TCP or UDP layer; skipping.")
    else:
        print("Packet does not have an IP layer; skipping.")

def flows_to_dataframe():
    global flow_data, flows
    rows = []
    for key, flow in flows.items():
        fwd_pkt_max = max(flow['fwd_packet_lengths'], default=0)
        bwd_pkt_max = max(flow['bwd_packet_lengths'], default=0)
        active_times = [(flow['timestamps'][i] - flow['timestamps'][i - 1]) for i in range(1, len(flow['timestamps']))]
        active_mean = sum(active_times) / len(active_times) if active_times else 0
        idle_mean = 0  # This can be implemented based on session times

        row = {
            'Destination Port': key[3],
            'Total Fwd Packets': flow['total_fwd_packets'],
            'Total Backward Packets': flow['total_bwd_packets'],
            'Total Length of Fwd Packets': flow['total_fwd_length'],
            'Total Length of Bwd Packets': flow['total_bwd_length'],
            'Fwd Packet Length Max': fwd_pkt_max,
            'Bwd Packet Length Max': bwd_pkt_max,
            'Flow Bytes/s': (flow['total_fwd_length'] + flow['total_bwd_length']) / (active_mean if active_mean > 0 else 1),
            'Flow Packets/s': (flow['total_fwd_packets'] + flow['total_bwd_packets']) / (active_mean if active_mean > 0 else 1),
            'Flow IAT Mean': sum(active_times) / len(active_times) if active_times else 0,
            'Flow IAT Std': pd.Series(active_times).std() if active_times else 0,
            'Flow IAT Max': max(active_times) if active_times else 0,
            'Fwd IAT Mean': sum(flow['fwd_iat']) / len(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Fwd IAT Std': pd.Series(flow['fwd_iat']).std() if flow['fwd_iat'] else 0,
            'Fwd IAT Max': max(flow['fwd_iat']) if flow['fwd_iat'] else 0,
            'Bwd IAT Mean': sum(flow['bwd_iat']) / len(flow['bwd_iat']) if flow['bwd_iat'] else 0,
            'Bwd IAT Std': pd.Series(flow['bwd_iat']).std() if flow['bwd_iat'] else 0,
            'SYN Flag Count': flow['syn_flag_count'],
            'PSH Flag Count': flow['psh_flag_count'],
            'ACK Flag Count': flow['ack_flag_count'],
            'FIN Flag Count': flow['fin_flag_count'],
            'Init_Win_bytes_forward': flow['init_win_bytes_forward'],
            'Init_Win_bytes_backward': flow['init_win_bytes_backward'],
            'Average Packet Size': ((flow['total_fwd_length'] + flow['total_bwd_length']) /
                                    (flow['total_fwd_packets'] + flow['total_bwd_packets'])
                                    if (flow['total_fwd_packets'] + flow['total_bwd_packets']) > 0 else 0),
            'Min Packet Length': min(flow['fwd_packet_lengths'] + flow['bwd_packet_lengths'], default=0),
            'Max Packet Length': max(flow['fwd_packet_lengths'] + flow['bwd_packet_lengths'], default=0),
            'Active Mean': active_mean,
            'Idle Mean': idle_mean,  # Placeholder for idle mean calculation
        }
        rows.append(row)

    return pd.DataFrame(rows)


def scan():
    sniff(filter="ip", prn=packet_callback, store=0, count=100)  # Adjust 'count' or use 'timeout' as needed

    df = flows_to_dataframe()

    try:
        rf_load = joblib.load('/Users/prathamvasa/Desktop/final-main/random_forest_model.pkl')
        #print(1)
        print("Columns in df:", df.columns)
        print("Model's expected features:", rf_load.get_params().get('feature_names', 'Not set'))

        correct_order = ['Destination Port', 'Total Fwd Packets', 'Total Backward Packets', 
                     'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
                     'Fwd Packet Length Max', 'Bwd Packet Length Max', 'Flow Bytes/s',
                     'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
                     'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Bwd IAT Mean',
                     'Bwd IAT Std', 'SYN Flag Count', 'PSH Flag Count', 'ACK Flag Count',
                     'FIN Flag Count', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
                     'Average Packet Size', 'Min Packet Length', 'Max Packet Length',
                     'Active Mean', 'Idle Mean']

        df = df[correct_order]

        df = df.apply(pd.to_numeric, errors='coerce')

        df_array = df.to_numpy()  # Convert DataFrame to NumPy array
        new = rf_load.predict(df_array)

        #print(2)
        df['prediction'] = new
        df['prediction'] = df['prediction'].apply(lambda x: 'Benign' if x == 0 else 'Malicious')  # Adjust based on your classes
        print(df['prediction'])
    except Exception as e:
        print(f"Couldn't find file {e}")

    print(df)
