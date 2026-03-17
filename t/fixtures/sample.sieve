require ["fileinto", "reject", "vacation", "envelope"];

# Filter mail from known senders
if address :is "from" "alice@example.com" {
    fileinto "VIP";
}

if address :is "from" "bob@example.org" {
    fileinto "Team";
}

# Auto-reply when on vacation
if envelope :is "to" "carol@example.com" {
    vacation :subject "Out of office"
             :from "carol@example.com"
             text:
Hi, I am out of the office until January 20.
For urgent matters, call +12125551234.
Carol White
.
             ;
}

# Reject spam
if header :contains "Subject" "URGENT MONEY TRANSFER" {
    reject "No thanks";
}
