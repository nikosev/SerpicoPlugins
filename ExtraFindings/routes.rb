require 'sinatra'
require 'json'
require './model/master'

# TODO doesn't enforce roles properly

get '/ExtraFindings/import' do
	if !File.file?("#{Dir.pwd()}/plugins/ExtraFindings/installed")
		return "Please run setup.sh for the ExtraFindings plugin."
	end

	# for now hand write the findings to import
	@sets = []

	# VulnDB: https://github.com/vulndb/data
	a = {}
	a["name"] = "VulnDB"
	a["link"] = "https://github.com/vulndb/data"
	a["license"] = "BSD 3-Clause"
	a["license_link"] = "https://github.com/vulndb/data/blob/master/LICENSE.md"
	@sets.push(a)

	# Burp Suite - Issue Definitions: https://portswigger.net/kb/issues
	b = {}
	b["name"] = "BurpSuite"
	b["link"] = "https://portswigger.net/kb/issues"
	b["license"] = "-"
	b["license_link"] = "#"
	@sets.push(b)

	haml :"../plugins/ExtraFindings/views/import"
end

post '/ExtraFindings/import' do
	if params["VulnDB"]
		import_vulndb
		options.finding_types.push("VulnDB")
	end
	if params["BurpSuite"]
		import_burpsuite
		if !(options.finding_types.include? 'BurpSuite')
			options.finding_types.push("BurpSuite")
		end
	end
	@success = "Imported findings"
	haml :"../plugins/ExtraFindings/views/import"
end

# Simple helper method rather than hand cleaning every string
def c(value)
	c_value = value.gsub("\n\n","<paragraph></paragraph>")
	c_value = c_value.gsub("`","'")
	return c_value
end


def import_vulndb()
	# Iterate the VulnDB database
	vulndb_dir = "#{Dir.pwd()}/plugins/ExtraFindings/data/VulnDB/db/"
	Dir.entries(vulndb_dir).each do |json_file|
		next if json_file == "." or json_file == ".."

		# Read in the JSON file and store as json obj
		file = File.read(vulndb_dir+json_file)
		json_data = JSON.parse(file)

		#### Change this portion if the VulnDB Schema changes
		finding = {}
		puts "|+| Importing #{json_data["title"]}"
		finding["title"] = c(json_data["title"])

		finding["overview"] = "<paragraph>"
		finding["overview"] += c(json_data["description"].join(" "))
		finding["overview"] += "</paragraph>"

		if json_data["fix"]["guidance"].kind_of?(Array)
			finding["remediation"] = "<paragraph>"
			finding["remediation"] += c(json_data["fix"]["guidance"].join(" "))
			finding["remediation"] += "</paragraph>"
		else
			finding["remediation"] = c(json_data["fix"]["guidance"])
		end

		finding["references"] = "<paragraph>VulnDB: https://github.com/vulndb/data</paragraph>"
		if json_data["references"] != nil
			json_data["references"].each do |ref|
				finding["references"] += "<paragraph>"+c(ref["url"])+"</paragraph>"
			end
		end

		finding["type"] = "VulnDB"
		finding["approved"] = true

		finding["risk"] = 1 if json_data["severity"] == "informational"
		finding["risk"] = 2 if json_data["severity"] == "low"
		finding["risk"] = 3 if json_data["severity"] == "medium"
		finding["risk"] = 4 if json_data["severity"] == "high"

		# TODO: add a true DREAD score calculator
		finding["damage"] = 1
		finding["reproducability"] = 1
		finding["exploitability"] = 1
		finding["affected_users"] = 1
		finding["discoverability"] = 1
		finding["dread_total"] = 5
		####

		# write the database
	    finding_db = TemplateFindings.create(finding)
	    finding_db.save
	end
end

def import_burpsuite()
	# Iterate the VulnDB database
	burpsuite_dir = "#{Dir.pwd()}/plugins/ExtraFindings/data/BurpSuite/db/*/"
	Dir[burpsuite_dir].each do |lang_dir|
		Dir.entries(lang_dir).each do |json_file|
			next if json_file == "." or json_file == ".."

			# Read in the JSON file and store as json obj
			file = File.read(lang_dir+json_file)
			json_data = JSON.parse(file)

			#### Change this portion if the VulnDB Schema changes
			finding = {}
			puts "|+| Importing #{json_data["title"]}"
			finding["title"] = c(json_data["title"])

			if json_data["description"].kind_of?(Array)
				finding["overview"] = ""
				json_data["description"].each do |rem|
					finding["overview"] += "<paragraph>"
					finding["overview"] += c(rem)
					finding["overview"] += "</paragraph>"
				end
			else
				finding["overview"] = "<paragraph>"
				finding["overview"] += c(json_data["description"])
				finding["overview"] += "</paragraph>"
			end

			if json_data["fix"]["guidance"].kind_of?(Array)
				finding["remediation"] = ""
				json_data["fix"]["guidance"].each do |rem|
					finding["remediation"] += "<paragraph>"
					finding["remediation"] += c(rem)
					finding["remediation"] += "</paragraph>"
				end
			else
				finding["remediation"] = c(json_data["fix"]["guidance"])
			end

			finding["references"] = ""
			if json_data["references"] != nil
				json_data["references"].each do |ref|
					finding["references"] += "<paragraph>"+c(ref["url"])+"</paragraph>"
				end
			end

			finding["type"] = "BurpSuite"
			finding["approved"] = true

			finding["risk"] = 0 if json_data["severity"] == "Information"
			finding["risk"] = 1 if json_data["severity"] == "Low"
			finding["risk"] = 2 if json_data["severity"] == "Medium"
			finding["risk"] = 3 if json_data["severity"] == "High"

			# TODO: add a true DREAD score calculator
			finding["damage"] = 1
			finding["reproducability"] = 1
			finding["exploitability"] = 1
			finding["affected_users"] = 1
			finding["discoverability"] = 1
			finding["dread_total"] = 5
			####

			finding["language"] = c(json_data["language"])

			# write the database
			finding_db = TemplateFindings.create(finding)
			finding_db.save
		end
	end
end
