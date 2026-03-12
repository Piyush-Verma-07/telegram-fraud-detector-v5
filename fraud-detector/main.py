# Import the scam detection function
from detector.scam_detector import analyze_message


# Ask the user to paste a suspicious message
message = input("Paste suspicious message:\n")


# Send the message to the detection function
score, reasons = analyze_message(message)


# Print the risk score
print("\nRisk Score:", score)


# Print reasons for the score
print("\nReasons:")

# If reasons list is empty print safe message
if not reasons:
    print("No suspicious patterns detected")

# Otherwise print all reasons
for r in reasons:
    print("-", r)