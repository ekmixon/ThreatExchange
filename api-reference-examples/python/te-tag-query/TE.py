# ================================================================
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
# ================================================================

# General Python dependencies
import os
import urllib
import urllib.parse
import urllib.request
import urllib.error
import json
import copy
import datetime
import re

# ================================================================
# HTTP-wrapper methods
# See also https://developers.facebook.com/docs/threat-exchange

# This is a class with all static methods -- no need to instantiate it.  I
# meant it to be just a module but ran into an implementation detail with
# updating module-private variables in Python; ended up just making it a class.


class Net:
    THREAT_DESCRIPTOR = "THREAT_DESCRIPTOR"
    DEFAULT_TE_BASE_URL = "https://graph.facebook.com/v6.0"
    TE_BASE_URL = DEFAULT_TE_BASE_URL
    APP_TOKEN = None

    # This is just a keystroke-saver / error-avoider for passing around
    # post-parameter field names.

    POST_PARAM_NAMES = {
        "indicator": "indicator",  # For submit
        "type": "type",  # For submit
        "descriptor_id": "descriptor_id",  # For update
        "description": "description",
        "share_level": "share_level",
        "status": "status",
        "privacy_type": "privacy_type",
        "privacy_members": "privacy_members",
        "tags": "tags",
        "add_tags": "add_tags",
        "remove_tags": "remove_tags",
        "confidence": "confidence",
        "precision": "precision",
        "review_status": "review_status",
        "severity": "severity",
        "expired_on": "expired_on",
        "first_active": "first_active",
        "last_active": "last_active",
        "related_ids_for_upload": "related_ids_for_upload",
        "related_triples_for_upload_as_json": "related_triples_for_upload_as_json",
        # Legacy : should have been named reactions_to_add, but isn't. :(
        "reactions": "reactions",
        "reactions_to_remove": "reactions_to_remove",
    }

    # ----------------------------------------------------------------
    # E.g. for overridiing
    #   https://graph.facebook.com/v{i}.{j}
    # to
    #   https://graph.facebook.com/v{x}.{y}
    @classmethod
    def setTEBaseURL(cls, baseURL):
        cls.TE_BASE_URL = baseURL

    # ----------------------------------------------------------------
    # Gets the ThreatExchange app token from an environment variable.  Feel
    # free to replace the app-token discovery method here with whatever is
    # most convenient for your project. However, be aware that app tokens
    # are like passwords and shouldn't be stored in the open.

    # I like to put export TX_ACCESS_TOKEN=$(cat ~/.txtoken) in my .bashrc where
    # ~/.txtoken is a mode-600 file.
    @classmethod
    def setAppTokenFromEnvName(cls, appTokenEnvName):
        if appTokenEnvName in os.environ:
            cls.APP_TOKEN = os.environ[appTokenEnvName]
        else:
            raise Exception(f"${appTokenEnvName} not found in environment.")

    # ----------------------------------------------------------------
    # Helper method for issuing a GET and returning the JSON payload.
    @classmethod
    def getJSONFromURL(cls, url):
        numTries = 0
        while True:
            numTries += 1
            [response, error] = cls.tryGET(url)
            if response != None:
                response = response.read()
                # Now make it a string
                response = response.decode("utf-8")
                return json.loads(response)
            elif error.code < 500 or error.code >= 600:
                raise error
            elif numTries > 4:
                raise error

    @classmethod
    def tryGET(cls, url):
        try:
            # The timeout is a heuristic
            response = urllib.request.urlopen(url, None, 60)
            return [response, None]
        except urllib.error.HTTPError as e:
            return [None, e]

    # ----------------------------------------------------------------
    # Looks up the "objective tag" ID for a given tag. This is suitable input for the /threat_tags endpoint.

    @classmethod
    def getTagIDFromName(cls, tagName, showURLs=False):
        url = (
            (
                ((cls.TE_BASE_URL + "/threat_tags") + "/?access_token=")
                + cls.APP_TOKEN
            )
            + "&text="
        ) + urllib.parse.quote(tagName)

        if showURLs:
            print("URL:")
            print(url)

        response = cls.getJSONFromURL(url)

        # The lookup will get everything that has this as a prefix.
        # So we need to filter the results. This loop also handles the
        # case when the results array is empty.
        #
        # Example: when querying for "media_type_video", we want the 2nd one:
        # { "data": [
        #   { "id": "9999338563303771", "text": "media_type_video_long_hash" },
        #   { "id": "9999474908560728", "text": "media_type_video" },
        #   { "id": "9889872714202918", "text": "media_type_video_hash_long" }
        #   ], ...
        # }
        data = response["data"]
        desired = list(filter(lambda o: o["text"] == tagName, data))
        return desired[0]["id"] if desired else None

    # ----------------------------------------------------------------
    # Looks up all descriptors with a given tag. Invokes a specified callback on
    # each page of IDs.

    @classmethod
    def processDescriptorIDsByTagID(cls, tagID, idProcessorCallback, **kwargs):
        verbose = kwargs.get("verbose", False)
        showURLs = kwargs.get("showURLs", False)
        includeIndicatorInOutput = kwargs.get("includeIndicatorInOutput", True)
        pageSize = kwargs.get("pageSize", 10)
        taggedSince = kwargs.get("taggedSince")
        taggedUntil = kwargs.get("taggedUntil")

        startURL = (
            (
                (
                    (((cls.TE_BASE_URL + "/") + tagID) + "/tagged_objects")
                    + "/?access_token="
                )
                + cls.APP_TOKEN
            )
            + "&limit="
        ) + str(pageSize)


        if taggedSince != None:
            startURL += f"&tagged_since={urllib.parse.quote(taggedSince)}"
        if taggedUntil != None:
            startURL += f"&tagged_until={urllib.parse.quote(taggedUntil)}"

        nextURL = startURL
        pageIndex = 0

        while nextURL != None:
            if showURLs:
                print("URL:")
                print(nextURL)

            # Format we're parsing:
            # {
            #   "data": [
            #     {
            #       "id": "9915337796604770",
            #       "type": "THREAT_DESCRIPTOR",
            #       "name": "7ef5...aa97"
            #     }
            #     ...
            #   ],
            #   "paging": {
            #     "cursors": {
            #       "before": "XYZIU...NjQ0h3Unh3",
            #       "after": "XYZIUk...FXNzVNd1Jn"
            #     },
            #     "next": "https://graph.facebook.com/v3.1/9999338387644295/tagged_objects?access_token=..."
            #   }
            # }

            response = cls.getJSONFromURL(nextURL)

            data = response["data"]

            nextURL = None
            if "paging" in response:
                paging = response["paging"]
                if "next" in paging:
                    nextURL = paging["next"]
            ids = []
            for item in data:
                itemID = item["id"]
                itemType = item["type"]
                if includeIndicatorInOutput:
                    itemName = item["name"]
                else:
                    del item["name"]
                if itemType != cls.THREAT_DESCRIPTOR:
                    continue
                if verbose:
                    print(json.dumps(item))
                ids.append(itemID)
            if verbose:
                info = {
                    "page_index": pageIndex,
                    "num_items_pre_filter": len(data),
                    "num_items_post_filter": len(ids),
                }

                print(json.dumps(info))

            idProcessorCallback(ids)

            pageIndex += 1

    # ----------------------------------------------------------------
    # Looks up all metadata for given IDs.
    @classmethod
    def getInfoForIDs(cls, ids, **kwargs):
        verbose = kwargs.get("verbose", False)
        showURLs = kwargs.get("showURLs", False)
        includeIndicatorInOutput = kwargs.get("includeIndicatorInOutput", True)

        # Check well-formattedness of descriptor IDs (which may have come from
        # arbitrary data on stdin).
        for id in ids:
            try:
                _ = int(id)
            except ValueError:
                raise Exception('Malformed descriptor ID "%s"' % id)

        # See also
        # https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-descriptor/v6.0
        # for available fields

        url = (
            (((cls.TE_BASE_URL + "/?access_token=") + cls.APP_TOKEN) + "&ids=")
            + ",".join(ids)
            + "&fields=raw_indicator,type,added_on,last_updated,confidence,owner,privacy_type,review_status,status,severity,share_level,tags,description,reactions,my_reactions"
        )


        if showURLs:
            print("URL:")
            print(url)

        response = cls.getJSONFromURL(url)

        descriptors = []
        for id, descriptor in response.items():
            if includeIndicatorInOutput == False:
                del descriptor["raw_indicator"]
            if verbose:
                print(json.dumps(descriptor))

            tags = descriptor.get("tags", None)
            tags = [] if tags is None else tags["data"]
            # Canonicalize the tag ordering and simplify the
            # structure to simply an array of tag-texts
            descriptor["tags"] = sorted(tag["text"] for tag in tags)

            if descriptor.get("description") is None:
                descriptor["description"] = ""

            descriptors.append(descriptor)

        return descriptors

    # ----------------------------------------------------------------
    # See also https://developers.facebook.com/docs/threat-exchange/reference/apis/threat-descriptors
    #
    # NOTE: THIS IS KNOWN TO NOT CORRECTLY HANDLE PAGINATION.  Please use the
    # tagged_objects endpoint as detailed above.

    @classmethod
    def doPowerSearch(cls, descriptorBatchProcessorCallback, urlParams, options):
        verbose = options.get("verbose", False)
        showURLs = options.get("showURLs", False)
        includeIndicatorInOutput = options.get("includeIndicatorInOutput", True)

        startURL = (
            (
                ((cls.TE_BASE_URL + "/threat_descriptors") + "/?access_token=")
                + cls.APP_TOKEN
            )
            + "&fields=raw_indicator,type,added_on,last_updated,confidence,owner,privacy_type,review_status,status,severity,share_level,tags,description,reactions,my_reactions"
        )


        for key, value in urlParams.items():
            startURL += f"&{key}={urllib.parse.quote(value)}"

        nextURL = startURL
        pageIndex = 0

        while nextURL is not None:
            if showURLs:
                print("URL:")
                print(nextURL)

            response = cls.getJSONFromURL(nextURL)

            data = response["data"]

            nextURL = None
            if "paging" in response:
                paging = response["paging"]
                if "next" in paging:
                    nextURL = paging["next"]

            descriptors = []
            for descriptor in data:
                if not includeIndicatorInOutput:
                    del descriptor["name"]

                # Canonicalize the tag ordering and simplify the
                # structure to simply an array of tag-texts
                tags = descriptor.get("tags", None)
                tags = [] if tags is None else tags["data"]
                tags = [tag["text"] for tag in tags]
                tags.sort()
                descriptor["tags"] = tags

                if descriptor.get("description") is None:
                    descriptor["description"] = ""

                descriptors.append(descriptor)

            if verbose:
                info = {"page_index": pageIndex, "num_items": len(data)}
                print(json.dumps(info))

            descriptorBatchProcessorCallback(descriptors)

            pageIndex += 1


    # ----------------------------------------------------------------
    # Returns error message or None.
    # This simply checks to see (client-side) if required fields aren't provided.
    @classmethod
    def validatePostPararmsForSubmit(cls, postParams):
        if postParams.get(cls.POST_PARAM_NAMES["descriptor_id"]) != None:
            return "descriptor_id must not be specified for submit."

        requiredFields = [
            cls.POST_PARAM_NAMES["indicator"],
            cls.POST_PARAM_NAMES["type"],
            cls.POST_PARAM_NAMES["description"],
            cls.POST_PARAM_NAMES["share_level"],
            cls.POST_PARAM_NAMES["status"],
            cls.POST_PARAM_NAMES["privacy_type"],
        ]


        missingFields = [
            fieldName if postParams.get(fieldName) is None else None
            for fieldName in requiredFields
        ]

        missingFields = [fieldName for fieldName in missingFields if fieldName != None]

        if not missingFields:
            return None
        elif len(missingFields) == 1:
            return f"Missing field {missingFields[0]}"
        else:
            return f'Missing fields {",".join(missingFields)}'

    # ----------------------------------------------------------------
    # Returns error message or None.
    # This simply checks to see (client-side) if required fields aren't provided.
    @classmethod
    def validatePostPararmsForUpdate(cls, postParams):
        if postParams.get(cls.POST_PARAM_NAMES["descriptor_id"]) is None:
            return "Descriptor ID must be specified for update."
        if postParams.get(cls.POST_PARAM_NAMES["indicator"]) is None:
            return (
                "Type must not be specified for update."
                if postParams.get(cls.POST_PARAM_NAMES["type"]) != None
                else None
            )

        else:
            return "Indicator must not be specified for update."

    # ----------------------------------------------------------------
    # Returns error message or None.
    # This simply checks to see (client-side) if required fields aren't provided.
    @classmethod
    def validatePostPararmsForCopy(cls, postParams):
        if postParams.get(cls.POST_PARAM_NAMES["descriptor_id"]) is None:
            return "Source-descriptor ID must be specified for copy."
        if postParams.get(cls.POST_PARAM_NAMES["privacy_type"]) is None:
            return "Privacy type must be specified for copy."
        if postParams.get(cls.POST_PARAM_NAMES["privacy_members"]) is None:
            return "Privacy members must be specified for copy."
        return None

    # ----------------------------------------------------------------
    # Does a single POST to the threat_descriptors endpoint.  See also
    # https://developers.facebook.com/docs/threat-exchange/reference/submitting
    @classmethod
    def submitThreatDescriptor(cls, postParams, showURLs, dryRun):
        errorMessage = cls.validatePostPararmsForSubmit(postParams)
        if errorMessage != None:
            return [errorMessage, None, None]

        url = (
            (cls.TE_BASE_URL + "/threat_descriptors") + "/?access_token="
        ) + cls.APP_TOKEN


        return cls._postThreatDescriptor(url, postParams, showURLs, dryRun)

    # ----------------------------------------------------------------
    # Does a single POST to the threat_descriptor ID endpoint.  See also
    # https://developers.facebook.com/docs/threat-exchange/reference/editing
    @classmethod
    def updateThreatDescriptor(cls, postParams, showURLs, dryRun):
        errorMessage = cls.validatePostPararmsForUpdate(postParams)
        if errorMessage != None:
            return [errorMessage, None, None]

        url = (
            (
                (cls.TE_BASE_URL + "/")
                + postParams[cls.POST_PARAM_NAMES["descriptor_id"]]
            )
            + "/?access_token="
        ) + cls.APP_TOKEN


        return cls._postThreatDescriptor(url, postParams, showURLs, dryRun)

    # ----------------------------------------------------------------
    @classmethod
    def copyThreatDescriptor(cls, postParams, showURLs, dryRun):
        errorMessage = cls.validatePostPararmsForCopy(postParams)
        if errorMessage != None:
            return [errorMessage, None, None]

        # Get source descriptor
        sourceID = postParams["descriptor_id"]
        # Not valid for posting a new descriptor
        del postParams["descriptor_id"]
        sourceDescriptor = cls.getInfoForIDs([sourceID], showURLs=showURLs)
        sourceDescriptor = sourceDescriptor[0]

        # Mutate necessary fields
        newDescriptor = copy.deepcopy(sourceDescriptor)
        newDescriptor["indicator"] = sourceDescriptor["raw_indicator"]
        del newDescriptor["raw_indicator"]
        if "tags" in newDescriptor and newDescriptor["tags"] is None:
            del newDescriptor["tags"]

        # The shape is different between the copy-from data (mapping app IDs to
        # reactions) and the post data (just a comma-delimited string of owner-app
        # reactions).
        if "reactions" in newDescriptor:
            del newDescriptor["reactions"]

        # Take the source-descriptor values and overwrite any post-params fields
        # supplied by the caller. Note: Python's dict-update method keeps the old
        # value for a given field name when both old and new are present so we
        # invoke it seemingly 'backward'.
        #
        # Example:
        # * x = {'a': 1, 'b': 2, 'c': 3}
        # * y = {'a': 1, 'b': 9, 'd': 12}
        # * After y.update(x) then x is unchanged and y is
        #       {'a': 1, 'b': 2, 'd': 12, 'c': 3}
        #
        # This means we want newDescriptor.update(postParams)
        newDescriptor.update(postParams)

        # Get rid of fields like last_upated from the source descriptor which
        # aren't valid for post
        postParams = {
            key: value
            for key, value in newDescriptor.items()
            if cls.POST_PARAM_NAMES.get(key) != None
        }

        return cls.submitThreatDescriptor(postParams, showURLs, dryRun)

    # ----------------------------------------------------------------
    # Code-reuse for submit and update
    @classmethod
    def _postThreatDescriptor(cls, url, postParams, showURLs, dryRun):
        for key, value in postParams.items():
            url += f"&{key}={urllib.parse.quote(str(value))}"
        if showURLs:
            print()
            print("URL:")
            print(url)
        if dryRun:
            print("Not doing POST since --dry-run.")
            return [None, None, ""]

        # Encode the inputs to the POST
        header = {"Content-Type": "text/json", "charset": "utf-8"}
        # This is a string
        data = urllib.parse.urlencode(postParams)
        # Turn it into a Python bytes object
        data = data.encode("ascii")

        # Do the POST
        try:
            response = urllib.request.urlopen(url, data)

            # Decode the outputs from the POST
            # This is a Python 'bytes'
            response = response.read()
            # Now make it a string
            response = response.decode("utf-8")
            responseBody = json.loads(response)
            responseCode = None

            return [None, None, responseBody]

        except urllib.error.HTTPError as e:
            responseBody = json.loads(e.read().decode("utf-8"))
            return [None, e, responseBody]

    # ----------------------------------------------------------------
    # This is for client-side creation-time filtering. We accept the same
    # command-line values as for tagged-time filtering which is done server-side
    # using PHP\strtotime which takes various epoch-seconds timestamps, various
    # format strings, and time-deltas like "-3hours" and "-1week".  Here we
    # re-invent some of PHP\strtotime.
    @classmethod
    def parseTimeStringToEpochSeconds(cls, mixedString):
        retval = cls._parseIntStringToEpochSeconds(mixedString)
        if retval != None:
            return retval

        retval = cls._parseDateTimeStringToEpochSeconds(mixedString)
        if retval != None:
            return retval

        retval = cls._parseRelativeStringToEpochSeconds(mixedString)
        return retval if retval != None else None

    # Helper for parseTimeStringToEpochSeconds to try epoch-seconds timestamps
    @classmethod
    def _parseIntStringToEpochSeconds(cls, mixedString):
        try:
            return int(mixedString)
        except ValueError:
            return None

    DATETIME_FORMATS = [
        "%Y-%m-%dT%H:%M:%S%z",  # TE server-side date format -- try first
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]

    # Helper for parseTimeStringToEpochSeconds to try various format-string
    # timestamps
    @classmethod
    def _parseDateTimeStringToEpochSeconds(cls, mixedString):
        for formatString in cls.DATETIME_FORMATS:
            retval = cls._parseDateTimeStringSingleFormat(mixedString, formatString)
            if retval != None:
                return retval
        return None

    # Helper for parseTimeStringToEpochSeconds to try a particular format-string
    # timestamp
    @classmethod
    def _parseDateTimeStringSingleFormat(cls, mixedString, formatString):
        try:
            return int(
                datetime.datetime.strptime(mixedString, formatString).timestamp()
            )
        except ValueError:
            return None

    # Helper for parseTimeStringToEpochSeconds to try various relative-time
    # indications
    @classmethod
    def _parseRelativeStringToEpochSeconds(cls, mixedString):
        retval = cls._parseRelativeStringMinute(mixedString)
        if retval != None:
            return retval
        retval = cls._parseRelativeStringHour(mixedString)
        if retval != None:
            return retval
        retval = cls._parseRelativeStringDay(mixedString)
        if retval != None:
            return retval
        retval = cls._parseRelativeStringWeek(mixedString)
        return retval if retval != None else None

    # Helper for parseTimeStringToEpochSeconds to try particular relative-time
    # indications.
    @classmethod
    def _parseRelativeStringMinute(cls, mixedString):
        pattern = re.compile("^-([0-9]+)minutes?$")
        output = pattern.match(mixedString)
        if output != None:
            count = int(output[1])
            return int(
                (
                    datetime.datetime.now() - datetime.timedelta(minutes=count)
                ).timestamp()
            )

        return None

    # Helper for parseTimeStringToEpochSeconds to try particular relative-time
    # indications.
    @classmethod
    def _parseRelativeStringHour(cls, mixedString):
        pattern = re.compile("^-([0-9]+)hours?$")
        output = pattern.match(mixedString)
        if output != None:
            count = int(output[1])
            return int(
                (
                    datetime.datetime.now() - datetime.timedelta(hours=count)
                ).timestamp()
            )

        return None

    # Helper for parseTimeStringToEpochSeconds to try particular relative-time
    # indications.
    @classmethod
    def _parseRelativeStringDay(cls, mixedString):
        pattern = re.compile("^-([0-9]+)days?$")
        output = pattern.match(mixedString)
        if output != None:
            count = int(output[1])
            return int(
                (
                    datetime.datetime.now() - datetime.timedelta(days=count)
                ).timestamp()
            )

        return None

    # Helper for parseTimeStringToEpochSeconds to try particular relative-time
    # indications.
    @classmethod
    def _parseRelativeStringWeek(cls, mixedString):
        pattern = re.compile("^-([0-9]+)weeks?$")
        output = pattern.match(mixedString)
        if output != None:
            count = int(output[1])
            return int(
                (
                    datetime.datetime.now() - datetime.timedelta(weeks=count)
                ).timestamp()
            )

        return None


# ================================================================
# Validator for client-side creation-time datetime parsing. Not written as unit
# tests per se since "-1week" et al. are dynamic things. Invoke via "python TE.py".
if __name__ == "__main__":

    def showParseTimeStringToEpochSeconds(mixedString):
        retval = Net.parseTimeStringToEpochSeconds(mixedString)
        readable = (
            None
            if retval is None
            else datetime.datetime.utcfromtimestamp(retval).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
        print("%-30s %-30s %s" % (mixedString, retval, readable))

    showParseTimeStringToEpochSeconds("1591626448")
    showParseTimeStringToEpochSeconds("2020-06-08T14:27:53")
    showParseTimeStringToEpochSeconds("2020-06-08T14:27:53Z")
    showParseTimeStringToEpochSeconds("2020-06-08T14:27:53+0400")
    showParseTimeStringToEpochSeconds("2020-06-08T14:27:53-0400")
    showParseTimeStringToEpochSeconds("2020-05-01T07:02:25+0000")
    showParseTimeStringToEpochSeconds("-1minute")
    showParseTimeStringToEpochSeconds("-3minutes")
    showParseTimeStringToEpochSeconds("-1hour")
    showParseTimeStringToEpochSeconds("-3hours")
    showParseTimeStringToEpochSeconds("-1day")
    showParseTimeStringToEpochSeconds("-3day")
    showParseTimeStringToEpochSeconds("-1week")
    showParseTimeStringToEpochSeconds("-3weeks")
    showParseTimeStringToEpochSeconds("nonesuch")
