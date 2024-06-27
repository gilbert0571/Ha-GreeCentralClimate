#!/usr/bin/python
# Do basic imports
import importlib.util
import socket
import base64
import re
import sys

import threading
import asyncio
import logging
import binascii
import os.path
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util
from datetime import datetime, timedelta
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.event import async_call_later
from homeassistant.components.climate import (ClimateEntity, PLATFORM_SCHEMA)

from homeassistant.helpers.entity import generate_entity_id

from homeassistant.components.climate.const import (
    HVACMode, ClimateEntityFeature,
    FAN_AUTO, FAN_LOW, FAN_MIDDLE, FAN_HIGH,
    PRESET_NONE, PRESET_SLEEP)

from homeassistant.const import (
    ATTR_UNIT_OF_MEASUREMENT, ATTR_TEMPERATURE, CONF_SCAN_INTERVAL,
    CONF_NAME, CONF_HOST, CONF_PORT, CONF_MAC, CONF_TIMEOUT, CONF_CUSTOMIZE, 
    STATE_ON, STATE_OFF, STATE_UNKNOWN, 
    UnitOfTemperature, PRECISION_WHOLE, PRECISION_TENTHS)

#from homeassistant.helpers.event import (async_track_state_change)
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.helpers.storage import Store
from homeassistant.core import Event, EventStateChangedData, callback
#from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity
from configparser import ConfigParser
from Crypto.Cipher import AES
try: import simplejson
except ImportError: import json as simplejson

REQUIREMENTS = ['pycryptodome']

_LOGGER = logging.getLogger(__name__)

SUPPORT_FLAGS = ClimateEntityFeature.TARGET_TEMPERATURE | ClimateEntityFeature.FAN_MODE | ClimateEntityFeature.PRESET_MODE | ClimateEntityFeature.TURN_ON | ClimateEntityFeature.TURN_OFF

CONF_TEMP_SENSOR = 'temp_sensor'

DEFAULT_NAME = 'Gree Climate'
BROADCAST_ADDRESS = '<broadcast>'
DEFAULT_PORT = 7000
DEFAULT_TARGET_TEMP_STEP = 1

# from the remote control and gree app
MIN_TEMP = 16
MAX_TEMP = 30

# fixed values in gree mode lists
HVAC_MODES = [HVACMode.AUTO, HVACMode.COOL, HVACMode.DRY, HVACMode.FAN_ONLY, HVACMode.HEAT, HVACMode.OFF]
FAN_MODES = [FAN_AUTO, FAN_LOW, 'medium-low', FAN_MIDDLE, 'medium-high', FAN_HIGH]
PRESET_MODES = [PRESET_NONE, PRESET_SLEEP,'Air Mode','SLeep + Air Mode']

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    vol.Required(CONF_HOST, default=BROADCAST_ADDRESS): cv.string,
    vol.Optional(CONF_SCAN_INTERVAL, default=timedelta(seconds=30)): (
        vol.All(cv.time_period, cv.positive_timedelta)),
    vol.Optional(CONF_TEMP_SENSOR, default={}): {
        cv.string: cv.entity_id
    },
})

def Pad(s):
    aesBlockSize = 16
    return s + (aesBlockSize - len(s) % aesBlockSize) * chr(aesBlockSize - len(s) % aesBlockSize)     

def ciperEncrypt(data, key="a3K8Bx%2r8Y7#xDh"):
    # _LOGGER.info('Crypto encrypt key: {}'.format(key))
    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    jsonStr = simplejson.dumps(data).replace(' ', '')
    padStr = Pad(jsonStr)
    encryptStr = cipher.encrypt(padStr.encode("utf-8"))
    finalStr = base64.b64encode(encryptStr).decode('utf-8')
    # _LOGGER.info('Crypto encrypt str: {}'.format(finalStr))
    return finalStr

def ciperDecrypt(data, key="a3K8Bx%2r8Y7#xDh"):
    decodeData = base64.b64decode(data)
    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    decryptData = cipher.decrypt(decodeData).decode("utf-8")
    replacedData = decryptData.replace('\x0f', '').replace(decryptData[decryptData.rindex('}')+1:], '')
    return simplejson.loads(replacedData)

async def async_setup_platform(hass, config, async_add_entities, discovery_info= None):
    _LOGGER.info('Setting up Gree climate platform')
    name = config.get(CONF_NAME)
    ip_addr = config.get(CONF_HOST)
    scan_interval = config.get(CONF_SCAN_INTERVAL)
    temp_sensor = config.get(CONF_TEMP_SENSOR)
    bridge = GreeBridge(hass, ip_addr, scan_interval, temp_sensor, async_add_entities)


class GreeBridge(object):
    def __init__(self, hass, host, scan_interval, temp_sensor, async_add_entities):
        self.hass = hass
        self.async_add_entities = async_add_entities
        self._scan_interval = scan_interval
        self._temp_sensor = temp_sensor
        self._host = host
        self._socket = None
        self._listening = False

        self._key = "a3K8Bx%2r8Y7#xDh"
        self.mac = None
        self.name = None
        self.subCnt = None
        self.uid = None
        self.devMap = {}
        
        store_key = 'gree2.devices'
        if host != BROADCAST_ADDRESS:
            store_key = store_key + '.' + host
        self.store = Store(hass, 1, store_key)

        self.start_listen()
#        async_call_later(self.hass, 10, self.scan_broadcast_now)
#        self.scan_broadcast()
        async_call_later(self.hass, 0, self.store_load)
    
    @callback
    def scan_broadcast_now(self, now):
        _LOGGER.info('scan_broadcast')
        reqData = {"t": "scan"}
        self.socket_send(reqData)
        
    async def store_load(self, now):
        dic = await self.store.async_load()
        if dic is not None:
            self.mac = dic['mac']
            #self.key = dic['key']
            self._host = dic['host']
            for item_mac in dic['sub']:
                self.devMap[item_mac] = Gree2Climate(self.hass, 'GREE Climate_' +
                                                     item_mac.rstrip('0'), item_mac, self, self._temp_sensor.get(item_mac))
            self.async_add_entities(self.devMap.values())
            async_track_time_interval(self.hass, self.get_all_state, self._scan_interval)
            _LOGGER.debug('Load stored dic: {} path:{} devMap:{}'.format(
                dic, self.store.path, self.devMap))
            #fore update entity id
            self.scan_broadcast()
        else:
            self.scan_broadcast()
    
    def data_to_save(self):
        return {
            'mac': self.mac,
            'host': self._host,
            'key': self._key,
            'sub': list(self.devMap.keys())
        }
        
    def start_listen(self):
        self._listening = True
        self.create_socket()
        self._thread = threading.Thread(target=self.socket_listen,args=())
        self._thread.daemon = True
        self._thread.start()

    def stop_listen(self):
        self._listening = False
        if self._socket is not None:
            _LOGGER.info('Closing socket')
            self._socket.close()
            self._socket = None

        self._thread.join()

    def create_socket(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # self._socket.bind(('', DEFAULT_PORT))
        except:
            _LOGGER.error('creat socket error')

    def get_all_state(self, now):
        for climate in self.devMap.values():
            climate.syncStatus()

    def socket_listen(self):
        while self._listening:
            if self._socket is None:
                continue
            try:
                data, address = self._socket.recvfrom(65535)
            except ConnectionResetError:
                _LOGGER.debug("Connection reset by peer")
                self.creat_socket()
                continue

            except socket.timeout as e:
                self.get_all_state(dt_util.now())
                continue

            except OSError as e:
                if e.errno == 9:  # when socket close, errorno 9 will raise
                    _LOGGER.debug("OSError 9 raise, socket is closed")
                else:
                    _LOGGER.error("unknown error when recv", exc_info=e)
                continue
            try:
                _LOGGER.info('socket received from {}:{}'.format(address, data.decode('utf-8', 'ignore')))
                receivedJson = simplejson.loads(data)
            except:
                continue

            if self.uid == None:
                self.uid = receivedJson['uid']
            if 'pack' in receivedJson:
                pack = receivedJson['pack']
                jsonPack = ciperDecrypt(pack, self._key)
                _LOGGER.info('Server received pack {}'.format(jsonPack))
                if jsonPack['t'] == 'dev':
                    (host,_) = address
                    self._host = host
                    #self.mid = jsonPack['mid']
                    self.mac = jsonPack['mac']
                    self.name = jsonPack['name']
                    self.subCnt = jsonPack['subCnt']
                    self.bind_device()
                elif jsonPack['t'] == 'bindOk':
                    self._key = jsonPack['key']
                    self.get_subdevices()
                elif jsonPack['t'] == 'subList':
                    devList = jsonPack['list']
                    _LOGGER.info('Scan Gree climate device list: {}'.format(devList))
                    if len(self.devMap) == 0:
                        update_only =False
                    else :
                        update_only =True
                    for item in devList:
                        item_mac = item['mac']
                        if not item_mac in self.devMap.keys():
                            self.devMap[item_mac] = Gree2Climate(self.hass, 'GREE Climate_' + item_mac.rstrip('0'), item_mac, self, self._temp_sensor.get(item_mac))
                    if len(self.devMap) < self.subCnt and jsonPack['i'] < self.subCnt:
                        self.get_subdevices(jsonPack['i'] + 1)
                    else :
                        self.store.async_delay_save(self.data_to_save, 0)
                        #subDevList = self.devMap.values()
                        #_LOGGER.info('All Gree climate device: {} subCnt: {}'.format(subDevList, len(self.devMap) ))
                        #self.async_add_entities(subDevList)
                        if update_only ==False :
                            self.async_add_entities(self.devMap.values())
                        if len(self.devMap) == 0:
                            self.stop_listen()
                        else:
                            async_track_time_interval(self.hass, self.get_all_state, self._scan_interval)

                elif jsonPack['t'] == 'dat':
                    self.devMap[jsonPack['mac']].dealStatusPack(jsonPack)
                elif jsonPack['t'] == 'res':
                    self.devMap[jsonPack['mac']].dealResPack(jsonPack)

    def socket_send(self, reqData):
        _LOGGER.info('socket send data {} to {}'.format(reqData, self._host))
        self._socket.sendto(simplejson.dumps(reqData).encode('utf-8'), (self._host, DEFAULT_PORT))

    def socket_send_pack(self, message, i=0, uid=None):
        _LOGGER.info('socket send pack {} to {}'.format(message, self._host))
        if uid == None:
            uid = self.uid
        pack = ciperEncrypt(message, self._key)
        reqData = {
            'cid': 'app',
            'i': i,
            't': 'pack',
            'uid': uid,
            'pack': pack,
            'tcid': self.mac
        }
        self.socket_send(reqData)

    def scan_broadcast(self):
        _LOGGER.info('scan_broadcast')
        reqData = {"t": "scan"}
        self.socket_send(reqData)

    def bind_device(self):
        message = {
            'mac': self.mac,
            't': 'bind',
            'uid': 0
        }
        self.socket_send_pack(message, 1, 0)

    def get_subdevices(self, i=0):
        message = {
            't': "subDev",
            'mac': self.mac,
            'i': i,
        }
        self.socket_send_pack(message)

class Gree2Climate(ClimateEntity):

    def __init__(self, hass, name, mac, bridge, temp_sensor):
        _LOGGER.info('Initialize the GREE climate device')
        self.hass = hass
        self.mac = mac

        self._attr_unique_id = 'com_gree2_' + mac.rstrip('0')
        
        self.entity_id = generate_entity_id("climate.{}", "gree2_" + mac,hass=hass)
        
        self.platform = 'gree2'

        self._available = True

        self._name = name

        self._bridge = bridge

        self._unit_of_measurement = hass.config.units.temperature_unit

        self._target_temperature = 26
        self._current_temperature = 26
        self._target_temperature_step = DEFAULT_TARGET_TEMP_STEP
        self._hvac_mode = HVACMode.OFF
        self._fan_mode = FAN_AUTO
        self._preset_mode = PRESET_NONE

        self._hvac_modes = HVAC_MODES
        self._fan_modes = FAN_MODES
        self._preset_modes = PRESET_MODES
        self._enable_turn_on_off_backwards_compatibility = False

        self._temp_sensor = temp_sensor
        if temp_sensor:
            async_track_state_change_event(hass, temp_sensor, self._async_temp_sensor_changed)
            
            
            temp_state = hass.states.get(temp_sensor)
            if temp_state:
                self._async_update_current_temp(temp_state)

        self._acOptions = {
            'Pow': 0,
            'Mod': str(self._hvac_mode.index(HVACMode.OFF)),
            'WdSpd': 0,
            'SetTem': 26,
            'SwhSlp': 0,
            'Air': 0,
        }
        
    @property
    def should_poll(self):
        # Return the polling state.
        return False

    @property
    def unique_id(self):
        # Return a unique ID.
        return self._attr_unique_id

    @property
    def available(self):
        # Return available of the climate device.
        return self._available

    @property
    def hidden(self):
        # Return hidden of the climate device.
        return not self._available

    @property
    def name(self):
        # Return the name of the climate device.
        return self._name

    @property
    def temperature_unit(self):
        # Return the unit of measurement.
        return self._unit_of_measurement

    @property
    def current_temperature(self):
        # Return the current temperature.
        return self._current_temperature

    @property
    def target_temperature(self):
        # Return the temperature we try to reach.
        return self._target_temperature

    @property
    def target_temperature_step(self):
        # Return the supported step of target temperature.
        return self._target_temperature_step

    @property
    def min_temp(self):
        # Return the minimum temperature.
        return MIN_TEMP
        
    @property
    def max_temp(self):
        # Return the maximum temperature.
        return MAX_TEMP

    @property
    def hvac_mode(self):
        # Return current operation mode ie. heat, cool, idle.
        return self._hvac_mode

    @property
    def hvac_modes(self):
        # Return the list of available operation modes.
        return self._hvac_modes

    @property
    def fan_mode(self):
        # Return the fan mode.
        return self._fan_mode

    @property
    def fan_modes(self):
        # Return the list of available fan modes.
        return self._fan_modes

    @property
    def preset_mode(self):
        # Return the preset mode.
        if self._acOptions['SwhSlp'] != 0 and self._acOptions['Air'] == 0:
            return PRESET_SLEEP
        if self._acOptions['SwhSlp'] == 0 and self._acOptions['Air'] != 0:
            return 'Air Mode'
        if self._acOptions['SwhSlp'] != 0 and self._acOptions['Air'] != 0:
            return 'SLeep + Air Mode'   
        return PRESET_NONE

    @property
    def preset_modes(self):
        # Return the list of available preset modes.
        return self._preset_modes

    @property
    def supported_features(self):
        # Return the list of supported features.
        return SUPPORT_FLAGS        

    def set_temperature(self, **kwargs):
        _LOGGER.info('set_temperature(): ' + str(kwargs.get(ATTR_TEMPERATURE)))
        # Set new target temperatures.
        if kwargs.get(ATTR_TEMPERATURE) is not None:
            # do nothing if temperature is none
            if not (self._acOptions['Pow'] == 0):
                # do nothing if HVAC is switched off
                _LOGGER.info('syncState with SetTem=' + str(kwargs.get(ATTR_TEMPERATURE)))
                self.syncState({ 'SetTem': int(kwargs.get(ATTR_TEMPERATURE))})

    def set_fan_mode(self, fan):
        _LOGGER.info('set_fan_mode(): ' + str(fan))
        # Set the fan mode.
        if not (self._acOptions['Pow'] == 0):
            _LOGGER.info('Setting normal fan mode to ' + str(self._fan_modes.index(fan)))
            self.syncState({'WdSpd': str(self._fan_modes.index(fan))})

    def set_hvac_mode(self, hvac_mode):
        _LOGGER.info('set_hvac_mode(): ' + str(hvac_mode))
        # Set new operation mode.
        if (hvac_mode == HVACMode.OFF):
            new_pow = 0 
            if self._hvac_mode == HVACMode.OFF:
                new_pow = 1
            _LOGGER.debug('set_hvac_mode, old hvac mode: {} new Pow: {}'.format(self._hvac_mode, new_pow) )
            self.syncState({'Pow': new_pow})
        else:
            self.syncState({'Mod': self._hvac_modes.index(hvac_mode), 'Pow': 1})

    def set_preset_mode(self, preset_mode):
        _LOGGER.info('set_preset_mode(): ' + str(preset_mode))
        # Set the fan mode.
        if self._acOptions['Pow'] == 0:
            return

        if preset_mode == PRESET_SLEEP:
            _LOGGER.info('Setting SwhSlp mode to 1')
            self.syncState({'SwhSlp': 1, 'Quiet': 1, 'Air': 0})
            return
        if preset_mode == 'Air Mode':
            _LOGGER.info('Setting Air mode to 1')
            self.syncState({'SwhSlp': 0, 'Quiet': 0, 'Air': 1})
            return
        
        if preset_mode == 'SLeep + Air Mode':
            _LOGGER.info('Setting SwhSlp and Air mode to 1')
            self.syncState({'SwhSlp': 1, 'Quiet': 1, 'Air': 1})
            return

        self.syncState({'SwhSlp': 0, 'Quiet': 0, 'Air': 0})

    async def async_added_to_hass(self):
        _LOGGER.info('Gree climate device added to hass()')
        self.syncStatus()

    def syncStatus(self):
        cmds = ['Pow', 'Mod', 'SetTem', 'WdSpd', 'Air', 'Blo', 'Health', 'SwhSlp', 'SwingLfRig', 'Quiet', 'SvSt']
        message = {
            'cols': cmds,
            'mac': self.mac,
            't': 'status'
        }
        self._bridge.socket_send_pack(message)
    
    def dealStatusPack(self, statusPack):
        if statusPack is not None:
            self._available = True
            for i, val in enumerate(statusPack['cols']):
                self._acOptions[val] = statusPack['dat'][i]
            _LOGGER.info('Climate {} status: {}'.format(self._name, self._acOptions))
            self.UpdateHAStateToCurrentACState()
            _LOGGER.info('in dealStatusPack() unique id=' + self.unique_id)
            #self.async_write_ha_state()
            self.schedule_update_ha_state()

    def dealResPack(self, resPack):
        if resPack is not None:
            for i, val in enumerate(resPack['opt']):
                self._acOptions[val] = resPack['val'][i]
            self.UpdateHAStateToCurrentACState()
            _LOGGER.info('in dealResPack() unique id=' + self.unique_id)
            #self.async_write_ha_state()
            self.schedule_update_ha_state()

    def syncState(self, options):
        commands = []
        values = []
        for cmd in options.keys():
            commands.append(cmd)
            values.append(int(options[cmd]))
        message = {
            'opt': commands,
            'p': values,
            't': 'cmd',
            'sub': self.mac
        }
        self._bridge.socket_send_pack(message)

    def UpdateHATargetTemperature(self):
        # Sync set temperature to HA
        self._target_temperature = self._acOptions['SetTem']
        _LOGGER.info('{} HA target temp set according to HVAC state to: {}'.format(self._name ,str(self._acOptions['SetTem'])))

    def UpdateHAHvacMode(self):
        # Sync current HVAC operation mode to HA
        if (self._acOptions['Pow'] == 0):
            self._hvac_mode = HVACMode.OFF
        else:
            self._hvac_mode = self._hvac_modes[self._acOptions['Mod']]
        _LOGGER.info('{} HA operation mode set according to HVAC state to: {}'.format(self._name, str(self._hvac_mode)))

    def UpdateHAFanMode(self):
        # Sync current HVAC Fan mode state to HA
        index = int(self._acOptions['WdSpd'])
        if index < len(self._fan_modes):
            self._fan_mode = self._fan_modes[int(self._acOptions['WdSpd'])]
            _LOGGER.info('{} HA fan mode set according to HVAC state to: {}'.format(self._name, str(self._fan_mode)))
        else:
            _LOGGER.info('{} HA fan mode set WdSpd to: {}'.format(self._name, str(self._acOptions['WdSpd'])))

    def UpdateHAStateToCurrentACState(self):
        self.UpdateHATargetTemperature()
        self.UpdateHAHvacMode()
        self.UpdateHAFanMode()

    @callback
    def _async_update_current_temp(self, state):
        try:
            float(state.state)
            pass
        except ValueError:
            return
        """Update thermostat with latest state from sensor."""
        try:
            self._current_temperature = self.hass.config.units.temperature(
                float(state.state), self._unit_of_measurement)
        except ValueError as ex:
            _LOGGER.error('Unable to update from sensor: %s', ex)

    async def _async_temp_sensor_changed(self,event: Event[EventStateChangedData]):
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        _LOGGER.info('temp_sensor state changed |' + str(entity_id) + '|' + str(old_state) + '|' + str(new_state))
        if new_state is None:
            return
        self._async_update_current_temp(new_state)
        _LOGGER.info('in _async_temp_sensor_changed() unique id=' + self.unique_id + ", -id="+ self._attr_unique_id)
        #self.async_write_ha_state()
        self.schedule_update_ha_state()
