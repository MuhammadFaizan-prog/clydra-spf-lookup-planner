// Include values commonly published by sending services (each resolved live when added).
// Providers change these; always confirm against the provider's own setup guide.
export interface Sender {
  name: string;
  include: string;
}

export const SENDERS: Sender[] = [
  { name: "Google Workspace", include: "_spf.google.com" },
  { name: "Microsoft 365", include: "spf.protection.outlook.com" },
  { name: "Amazon SES", include: "amazonses.com" },
  { name: "SendGrid", include: "sendgrid.net" },
  { name: "Mailgun", include: "mailgun.org" },
  { name: "Mailchimp", include: "servers.mcsv.net" },
  { name: "Mandrill", include: "spf.mandrillapp.com" },
  { name: "Postmark", include: "spf.mtasv.net" },
  { name: "Brevo", include: "spf.brevo.com" },
  { name: "Zoho Mail", include: "zohomail.com" },
  { name: "Zendesk", include: "mail.zendesk.com" },
  { name: "Salesforce", include: "_spf.salesforce.com" },
  { name: "MailerLite", include: "_spf.mlsend.com" },
  { name: "Marketo", include: "mktomail.com" },
];
