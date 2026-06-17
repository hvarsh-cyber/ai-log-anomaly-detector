from detector.log_generator import LogGenerator
from detector.anomaly_detector import AnomalyDetector

def main():
    print("=" * 50)
    print("AI Log Anomaly Detector")
    print("=" * 50)
    
    # Step 1: Generate realistic log data
    generator = LogGenerator()
    log_file = generator.generate_dataset()
    
    # Step 2: Run AI anomaly detection
    detector = AnomalyDetector(log_file=log_file)
    detector.run()

if __name__ == "__main__":
    main()