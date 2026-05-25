resource "cloudflare_zero_trust_device_posture_rule" "%[1]s" {
	account_id = "%[2]s"
	name       = "%[1]s"
	type       = "gateway"
}
