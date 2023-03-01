#!/usr/bin/python3
import sys, logging
from yaml import load as load_yaml
from json import loads as json_loads, dumps as json_dumps
from re import match, escape
from requests import Session, Request

# TODO: REMOVE THIS IMPORT?
from time import time, localtime, strftime

''' Log(config)
Allows for configurable logging with extra logic applied
Methods can be expanded for additional logging requirements
'''
class Log(object):

    def __init__(self, config):

        log_file     = config.get('file')
        enable_debug = config.get('debug')

        # Instantiate a Logger and StreamHandler for it
        logger = logging.getLogger('tsds-telegraf')
        sh     = logging.StreamHandler()

        # Set the logfile
        if log_file:
            logging.basicConfig(filename=log_file)

        # Set the logging level
        if enable_debug:
            logger.setLevel(logging.DEBUG)
            sh.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
            sh.setLevel(logging.INFO)

        # Define the log output format and then add the StreamHandler to the Logger
        sh.setFormatter(logging.Formatter('[%(name)s] [%(levelname)s]: %(message)s'))
        logger.addHandler(sh)

        self.logger     = logger
        self.debug_mode = enable_debug

    # Logger Get & Set
    @property
    def logger(self):
        return self.__logger
    @logger.setter
    def logger(self, logger):
        self.__logger = logger

    # Debug Mode Get & Set
    @property
    def debug_mode(self):
        return self.__debug_mode
    @debug_mode.setter
    def debug_mode(self, debug_mode):
        self.__debug_mode = debug_mode

    # Helper method to pretty print data structures
    def _dumper(self, data):
        try:
            return json_dumps(data)
        except TypeError as e:
            self.logger.error('Could not create data dump for logging: {}'.format(e))
            return data

    # Define the logging methods of the configured logger
    # The check is an optimization to reduce message evaluation
    # Error logging is always available and has no check
    def debug(self, msg, dump=False):
        if self.logger.isEnabledFor(logging.DEBUG):
            msg = self._dumper(msg) if dump else msg
            self.logger.debug(msg)

    def info(self, msg, dump=False):
        if self.logger.isEnabledFor(logging.INFO):
            msg = self._dumper(msg) if dump else msg
            self.logger.info(msg)

    def warn(self, msg, dump=False):
        if self.logger.isEnabledFor(logging.WARNING):
            msg = self._dumper(msg) if dump else msg
            self.logger.warning(msg)

    def error(self, msg, dump=False):
        msg = self._dumper(msg) if dump else msg
        self.logger.error(msg)


''' Client(config, Log)
Allows for easy creation of a configurable web service client
Currently hard-coded to only support TSDS push services.
'''
class Client(object):

    def __init__(self, config, log):
        
        self.username = config.get('username')
        self.password = config.get('password')
        self.url      = config.get('url')
        self.timeout  = config.get('timeout')

        # Create a Session and Request object used for POSTing requests
        self.session      = Session()
        self.session.auth = (self.username, self.password)

        self.log = log
        self.log.debug('Initialized Client instance')

    # Username Get & Set
    @property
    def username(self):
        return self.__username
    @username.setter
    def username(self, username):
        self.__username = username

    # Password Get & Set
    @property
    def password(self):
        return self.__password
    @password.setter
    def password(self, password):
        self.__password = password

    # URL Get & Set
    @property
    def url(self):
        return self.__url
    @url.setter
    def url(self, url):
        url = url if url[-1] != '/' else url[:-1]
        self.__url = url

    # Timeout Get & Set
    @property
    def timeout(self):
        return self.__timeout
    @timeout.setter
    def timeout(self, timeout):
        self.__timeout = int(timeout) if timeout else 15

    # Session Get & Set
    @property
    def session(self):
        return self.__session
    @session.setter
    def session(self, session):
        self.__session = session

    # Request Get & Set
    @property
    def request(self):
        return self.__request
    @request.setter
    def request(self, request):
        self.__request = request

    # Log Get & Set
    @property
    def log(self):
        return self.__log
    @log.setter
    def log(self, log):
        self.__log = log

    # Takes data and pushes its JSON string to TSDS via POST
    # Return will evaluate to true if an error occurred
    def push(self, data):
      
        # Stringify the data for POSTing
        try:
            data_str = json_dumps(data)
        except RuntimeError as e:
            self.log.error('push(): Error while attempting to create JSON string from data: {}\n{}'.format(data, e))
            return None

        # Create the data dict for requests to POST
        post_data = {'method': 'add_data', 'data': data_str}

        # POST the data to the TSDS push service URL
        try:

            # Update the PreparedRequest's data payload
            req = Request('POST', self.url, data=post_data)
            req = self.session.prepare_request(req)

            # Send the prepared POST request
            res = self.session.send(req, timeout=self.timeout)

            # Raise an error when a 4XX or 5XX status code was received
            res.raise_for_status()

        except RuntimeError as e:
            self.request.data = None
            self.log.error('push(): Error while attempting to POST data: {}'.format(e))
            return None
    
        self.log.info('Pushed {} updates to TSDS'.format(len(data)))
        if self.log.debug_mode and len(data) > 0:
            self.log.debug('Sample update from batch:')
            self.log.debug(data[0])

        return 1


class CacheEntry(object):
    
    def __init__(self, timestamp, created, raw_json):
        self.timestamp = timestamp
        self.alignment = None
        self.data      = {}

        # TODO: REMOVE THESE PROPS
        self.created   = created
        self.raw       = raw_json

    # TODO: REMOVE THIS PROP
    @property
    def created(self):
        return self.__created
    @created.setter
    def created(self, time):
        self.__created = time
    @property
    def raw(self):
        return self.__raw
    @raw.setter
    def raw(self, raw):
        self.__raw = raw

    # Timestamp
    @property
    def timestamp(self):
        return self.__timestamp
    @timestamp.setter
    def timestamp(self, timestamp):
        self.__timestamp = int(timestamp)
    # Aligned Timestamp
    @property
    def alignment(self):
        return self.__alignment
    @alignment.setter
    def alignment(self, alignment):
        self.__alignment = alignment
    # Data Dictionary
    @property
    def data(self):
        return self.__data
    @data.setter
    def data(self, data):
        self.__data = data


''' Transformer(collections, Log)
Uses configurable definitions to translate Telegraf metrics to TSDS measurements.
Performs data transormations including rate calculations.
'''
class Transformer(object):

    # More than meets the eye
    def __init__(self, collections, log):
        self.collections = collections
        self.log         = log
        self.cache       = {}
        self.log.debug('Initialized DataTransformer instance')

    @property
    def collections(self):
        return self.__collections
    @collections.setter
    def collections(self, collections):
        self.__collections = collections
    @property
    def log(self):
        return self.__log
    @log.setter
    def log(self, log):
        self.__log = log
    @property
    def cache(self):
        return self.__cache
    @cache.setter
    def cache(self, cache):
        self.__cache = cache if isinstance(cache,dict) else dict()


    def _validate_metric(self, metric):
        '''
        Validates that all metric components exist.
        Returns False when any components are missing.
        '''
        errors = 0
        for component in ['name', 'fields', 'tags', 'timestamp']:
            if metric.get(component) == None:
                errors += 1
                self.log.debug('Metric missing "{}" component'.format(component))
        return (errors == 0)


    def _align_timestamp(self, entry, cached, interval):
        '''
        Aligns timestamps to the most appropriate rounded collection interval.
        This is a workaround for a TSDS bug that always uses the rounded floor of the timestamp.
        '''
        mod = entry.timestamp % interval

        # Use the current timestamp if it is already aligned
        if mod == 0:
            return entry.timestamp

        # Default alignment is rounded down
        aligned = entry.timestamp - mod

        # Check the default alignment against a previous one if it exists
        # If it's the same, the new data is rounded to the next interval.
        # Otherwise, the default rounded down alignment is used
        if cached and cached.alignment and cached.alignment == aligned:
            return int(aligned + interval)
        return int(aligned)


    def _calculate_rate(self, value, name, cached, interval, timestamp):   
        ''' Calculate a rate using new data and the cached entry '''

        # Validate everything needed for calculation is available
        if cached != None:
            if timestamp == None:
                self.log.error('_calculate_rate(): Missing current timestamp for "{}"'.format(name))
                return None
        
            elif value == None:
                self.log.error('_calculate_rate(): Missing current value for "{}"'.format(name))
                return None

            elif cached.timestamp == None:
                self.log.error('_calculate_rate(): Missing cached timestamp for "{}"'.format(name))
                return None

            elif cached.data.get(name) == None:
                self.log.error('_calculate_rate(): Missing cached value for "{}"'.format(name))
                return None
        else:
            return None

        # Calculate the time delta between entries
        time_delta = timestamp - cached.timestamp

        # Catch deltas that are negative or 0
        if time_delta <= 0:
            self.log.error('_calculate_rate(): Erroneous time delta ({}s) detected for "{}"'.format(time_delta, name))
            return None

        cached_value = cached.data.get(name)

        # Calculate the value delta between entries
        value_delta = value - cached_value

        # Handle counter overflow/reset
        if value < cached_value:

            # 64-bit counters
            if value > 2**32:
                value_delta = 2**64 - cached_value + value
            # 32-bit counters
            else:
                value_delta = 2**32 - cached_value + value

        # Return the calculated rate
        return value_delta / time_delta


    # Parses a Telegraf Metric JSON string and returns a Measurement for TSDS ingestion
    def get_measurement(self, json_str):

        # Attempt to load the JSON string as a dict
        try:
            metric = json_loads(json_str)
        except RuntimeError as e:
            self.log.error('get_measurement(): Unable to parse JSON string from STDIN, skipping ({}): {}'.format(line, e))
            return None

        # Validate the Metric
        if not self._validate_metric(metric):
            return None

        # Get the collection configuration using the metric name
        collection = self.collections.get(metric.get('name'))

        # Check whether the metric name has a configured collection in the plugin
        if collection == None:
            self.log.error('get_measurement(): Collection "{}" is not configured'.format(metric.get('name')))
            return None

        # An array of measurement dicts that will be returned and written to TSDS
        output = []

        # Get the collection components
        tsds_name = collection.get('tsds_name')
        interval  = collection.get('interval')

        # Get the metric components
        name      = metric.get('name')
        tags      = metric.get('tags')
        fields    = metric.get('fields')
        timestamp = int(metric.get('timestamp'))

        # Initialize the metadata and values dicts and error flags
        metadata, values = dict(), dict()
        meta_err = False

        # Parse metadata from tags
        for tag_map in collection.get('metadata'):
            tag_name  = tag_map.get('from')
            meta_name = tag_map.get('to')
            optional  = tag_map.get('optional')

            tag = tags.get(tag_name)

            # Set the metadata to the tag value
            if tag != None:
                metadata[meta_name] = tag

            elif not optional:
                self.log.error('get_measurement(): "{}" Metric missing metadata for "{}"'.format(name, meta_name))
                meta_err = True

        # Return when required metadata is missing
        if meta_err:
            return None

        # Make a cache ID using the name and metadata combination
        cache_id = name + '|' + '|'.join(sorted(metadata.values()))

        # TODO: REMOVE THIS
        now = int(time())

        # Create a new cache entry for the current data
        entry = CacheEntry(timestamp, now, json_str)

        # Get an existng cache entry
        cached_entry = self.cache.get(cache_id)

        # TODO: REMOVE THIS BLOCK
        bad = None
        if cached_entry != None:

            tform = "%Y-%m-%d %H:%M:%S"
    
            if entry.timestamp == cached_entry.timestamp:
                self.log.error("[TIME ERROR] New timestamp identical to last cached timestamp")
                bad = cache_id
            elif entry.timestamp < cached_entry.timestamp:
                self.log.error("[TIME ERROR] New timestamp occurring before last cached timestamp")
                bad = cache_id
            elif cached_entry.timestamp < 1600000000:
                self.log.error("[TIME ERROR] Cached timestamp for the metadata combination was bad")
                bad = cache_id
            elif entry.timestamp > int(now + 86400):
                self.log.error("[TIME ERROR] New timestamp occuring too far into the future")
                bad = cache_id

            if bad != None:
                self.log.error("METADATA ID: {}".format(cache_id))
                self.log.error("DATA TIMESTAMP   (NEW): {}".format(strftime(tform, localtime(entry.timestamp))))
                self.log.error("DATA TIMESTAMP (CACHE): {}".format(strftime(tform, localtime(cached_entry.timestamp))))
                self.log.error("SYSTEM TIME      (NEW): {}".format(strftime(tform, localtime(now))))
                self.log.error("SYSTEM TIME    (CACHE): {}".format(strftime(tform, localtime(cached_entry.created))))
                self.log.error("RAW JSON (CACHE): {}".format(cached_entry.raw))
                self.log.error("RAW JSON (NEW):   {}".format(entry.raw))


        # Parse values from fields
        for field_map in collection.get('fields', []):

            field_name = field_map.get('from')
            value_name = field_map.get('to')
            is_rate    = (field_map.get('rate') != None)

            value = fields.get(field_name)

            # The value requires rate calculation
            if is_rate:
       
                values[value_name] = self._calculate_rate(value, value_name, cached_entry, interval, timestamp)

                # Add the raw value to the cache entry for future rate calculations
                entry.data[value_name] = value

                if cached_entry != None and values[value_name] == None:
                    self.log.error('get_measurement(): Could not calculate "{}" rate for "{}"'.format(value_name, cache_id))

            # No rate calculation, just add to values
            else:
                values[value_name] = value

        # Get the aligned timestamp for the TSDS interval
        aligned_time = self._align_timestamp(entry, cached_entry, interval)

        # Set the aligned timestamp for the current entry
        entry.alignment = aligned_time

        # Overwrite any existing entry in the cache with the new one
        self.cache[cache_id] = entry
        
        # Create a dict of measurement data to push to TSDS
        measurement = {
            "type":     tsds_name,
            "time":     aligned_time,
            "meta":     metadata,
            "values":   values,
            "interval": interval
        }

        output.append(measurement)

        # Return here unless we want optional metadata
        if 'optional_metadata' not in collection:
            return output, bad

        # Flag to indicate optional metadata fields are present
        has_opt = False

        for opt_meta in collection.get('optional_metadata', []):

            tag_name  = opt_meta['from']
            meta_name = opt_meta['to']

            # Absolute match for tag names
            if tag_name in tags:
                metadata[meta_name] = tags[tag_name]

            # Wildcard matching for tag names
            elif "*" in tag_name:

                # Get the data for each Telegraf tag that matches our wildcard
                optional_tags = [tags[t] for t in tags if re.match(tag_name, t)]

                # Map matches to a specified field_name if configured
                if opt_meta.get('field_name'):
                    optional_tags = [{opt_meta['field_name']: m} for m in optional_tags]

                if len(optional_tags):
                    metadata[meta_name] = optional_tags
                    has_opt = True

        # Add a separate object for optional metadata to the output for TSDS
        if has_opt:
            metadata_data = {
                "meta": metadata,
                "time": aligned_time,
                "type": tsds_name + ".metadata"
            }
            output.append(metadata_data)

        self.log.debug('Transform produced the following data:')
        self.log.debug(output, True)
            
        return output, bad


''' Main processing loop.
Takes config file from command-line arguments to configure classes.
Reads Telegraf JSON input from STDIN and produces TSDS updates in batches.
'''
if __name__ == '__main__':
    
    if len(sys.argv) < 2:
        print("Usage: {} <config file>".format(sys.argv[0]))
        sys.exit(1)
    else:
        config_file = sys.argv[1]

        # Read the YAML configuration
        with open(config_file) as f:
            config = load_yaml(f)

    # Instantiate the Log, Client, and Transformer objects
    log         = Log(config.get('logging'))
    client      = Client(config.get('client'), log)
    transformer = Transformer(config.get('collections'), log)

    log.info('Initialized TSDS-Telegraf execd plugin')

    # Batch array for storing metrics transformed into TSDS measurements
    batch = []
    
    # Get the number of updates to send in a batch
    batch_size = config.get('batch_size', 10)

    # Process Metric JSON strings from STDIN
    for line in sys.stdin:

        # Parse the Metric JSON and return a TSDS measurement
        # Any rate calculation or other operation has been applied to the measurement
        measurement, bad = transformer.get_measurement(line)

        if bad != None:
            log.error('main(): Line triggered a timestamp bug: {}'.format(line))

        # For some reason, we could not create a measurement from the JSON
        if measurement == None:
            log.error('main(): Line from STDIN did not produce any update messages: {}'.format(line))
            continue

        # Add the measurement data to the batch
        batch.extend(measurement)

        # Push the batch to TSDS once its ready
        if len(batch) >= batch_size:

            res = client.push(batch)

            # Reset the batch when it was successfully pushed
            if res:
                batch = []
            
            # Exit and let Telegraf restart the plugin if data can't be pushed
            else:
                sys.exit()

