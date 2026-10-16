// Sample scenario: a company on Google Workspace that already sends through SendGrid, Mailgun and
// Mailchimp, and now wants to add Salesforce. example.com is reserved for documentation.
export const SAMPLE_DOMAIN = "example.com";
export const SAMPLE_CURRENT = "v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:servers.mcsv.net ~all";
export const SAMPLE_PLANNED = "v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:servers.mcsv.net include:_spf.salesforce.com ~all";
