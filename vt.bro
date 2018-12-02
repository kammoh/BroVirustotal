@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module MalwareHashCheck;

export {
    redef enum Notice::Type += {
        VTHashMatch,
        VTMalicious
    };

    type VTResponse: record
    {
        positives : string;
        total : string;
    };

    const match_file_types = /application\/x-executable/ |
                             /application\/x-dosexec/ |
                             /application\/vnd.ms-cab-compressed/ |
                             /application\/pdf/ |
                             /application\/x-shockwave-flash/ |
                             /application\/x-java-applet/ |
                             /application\/jar/ |
                             /video\/mp4/ &redef;

    const url = "https://www.virustotal.com/vtapi/v2/file/report" &redef;

    const vt_apikey = "38ea87eb8e2238fb1ab27c9277600eb43ac665ce8164cbf3c4e9d4408ad043f8" &redef;

}



global checked_hashes: set[string] &synchronized;
global matched_hashes: set[string] &synchronized;

## Extract integer (or quoted string) value from a key:value (or key:"value").
function extract_value(str: string) : string
    {
    local s = split1(str, /:/)[2];
    s = sub(s, /^\"/, "");
    return sub(s, /\"$/, "");
    }

function parse_vt_response(json: string) : VTResponse
    {
    local resp: VTResponse;

    resp$total = "N/A";
    resp$positives = "N/A";

    local top = split_string(json, /,|\}/);
    for ( i in top )
        {   
            local data = top[i];
            if ( strstr(data, "positives\":") > 0 )
                {
                resp$positives = extract_value(data);
                }
            else if ( strstr(data, "total\":") > 0 )
                {
                resp$total = extract_value(data);
                }
        }
    

    return resp;
    }

function do_lookup(hash: string, source: string, fi: Notice::FileInfo)
    {
    
    # https://www.virustotal.com/vtapi/v2/file/report?apikey=<api-key>&resource=<hash>
        local data = fmt("resource=%s", hash);
        local key = fmt("-d apikey=%s",vt_apikey);
        local my_url = fmt("%s?apikey=%s&resource=%s", url, vt_apikey, hash);
        local req: ActiveHTTP::Request = ActiveHTTP::Request($url=my_url, $method="GET");
        when (local res = ActiveHTTP::request(req))
            {
            if ( |res| > 0)
                {
                if ( res?$body ) 
                    {
                    local body = res$body;
                    local resp : VTResponse = parse_vt_response(body);
                    local positives: int = to_int(resp$positives);
                    local total: int = to_int(resp$total);
                    local threat : double = to_double(resp$positives)/to_double(resp$total) * 100.0;

                    local msg = fmt("detection for file-hash %s over %s = [%d/%d] (%%%.2f)", hash, source, positives, total, threat);
                    if ( source == "HTTP" )
                        {
                        print(msg);
                        }
                    # local n: Notice::Info = Notice::Info($note=VTHashMatch, $msg=msg);
                    # Notice::populate_file_info2(fi, n);
                    # NOTICE(n);
                    }
                }
            }
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
        if ( kind == "sha1" && f?$info && f$info?$mime_type)# && match_file_types in f$info$mime_type)
            {
                # TODO check the list of already looked-up hashes
                do_lookup(hash, f$source, Notice::create_file_info(f));

            }
    }


event bro_init()
    {
        print "Hello from vt.bro @bro_init event";
    }
