// StickFixture — one HomeKit Lightbulb accessory per patched fixture.
//
// State is owned by the platform-wide StateRegistry. We read on .onGet,
// write on .onSet, and subscribe to changes so the HomeKit-displayed
// values track the registry (e.g. when a zone updates this fixture).

import type {
  CharacteristicValue,
  PlatformAccessory,
  Service,
} from 'homebridge';

import { Fixture } from './config.js';
import { HomeKitLightState } from './color/types.js';
import { StickController } from './controller.js';
import type { DmxPlatform } from './platform.js';
import { CHARACTERISTIC_UPDATE_DELAY_MS } from './settings.js';
import { StateRegistry } from './stateRegistry.js';

export class StickFixture {
  private pending: NodeJS.Timeout | null = null;
  private bulb: Service;

  constructor(
    private readonly platform: DmxPlatform,
    private readonly accessory: PlatformAccessory,
    private readonly fixture: Fixture,
    private readonly controller: StickController,
    private readonly registry: StateRegistry,
  ) {
    const C = platform.Characteristic;
    const info = accessory.getService(platform.Service.AccessoryInformation);
    info?.setCharacteristic(C.Manufacturer, 'Stick-DE3 DMX')
        ?.setCharacteristic(C.Model, fixture.profile.name)
        ?.setCharacteristic(C.SerialNumber, fixture.id);

    this.bulb =
      accessory.getService(platform.Service.Lightbulb)
      ?? accessory.addService(platform.Service.Lightbulb, fixture.name);

    this.bulb.setCharacteristic(C.Name, fixture.name);

    const chars = fixture.profile.model.characteristics;

    this.bulb.getCharacteristic(C.On)
      .onGet(() => registry.get(fixture.id).on)
      .onSet((v) => {
        registry.update(fixture.id, { on: Boolean(v) });
        this.schedule();
      });

    if (chars.includes('Brightness')) {
      this.bulb.getCharacteristic(C.Brightness)
        .onGet(() => registry.get(fixture.id).brightness)
        .onSet((v: CharacteristicValue) => {
          registry.update(fixture.id, { brightness: Number(v) });
          this.schedule();
        });
    }
    if (chars.includes('Hue')) {
      this.bulb.getCharacteristic(C.Hue)
        .onGet(() => registry.get(fixture.id).hue ?? 0)
        .onSet((v) => {
          registry.update(fixture.id, { hue: Number(v) });
          this.schedule();
        });
    }
    if (chars.includes('Saturation')) {
      this.bulb.getCharacteristic(C.Saturation)
        .onGet(() => registry.get(fixture.id).saturation ?? 0)
        .onSet((v) => {
          registry.update(fixture.id, { saturation: Number(v) });
          this.schedule();
        });
    }
    if (chars.includes('ColorTemperature')) {
      this.bulb.getCharacteristic(C.ColorTemperature)
        .onGet(() => registry.get(fixture.id).colorTemperatureMireds ?? 200)
        .onSet((v) => {
          // CCT change implies white mode; zero saturation.
          registry.update(fixture.id, {
            colorTemperatureMireds: Number(v),
            saturation: 0,
          });
          this.schedule();
        });
    }

    // Refresh HomeKit characteristics whenever this fixture's state changes
    // in the registry (e.g. via a zone set, or another channel of itself).
    registry.onChange((changedId) => {
      if (changedId !== fixture.id) return;
      this.pushFromRegistry();
    });
  }

  private pushFromRegistry(): void {
    const s = this.registry.get(this.fixture.id);
    const C = this.platform.Characteristic;
    const chars = this.fixture.profile.model.characteristics;
    this.bulb.updateCharacteristic(C.On, s.on);
    if (chars.includes('Brightness')) this.bulb.updateCharacteristic(C.Brightness, s.brightness);
    if (chars.includes('Hue') && s.hue != null) this.bulb.updateCharacteristic(C.Hue, s.hue);
    if (chars.includes('Saturation') && s.saturation != null) this.bulb.updateCharacteristic(C.Saturation, s.saturation);
    if (chars.includes('ColorTemperature') && s.colorTemperatureMireds != null) {
      this.bulb.updateCharacteristic(C.ColorTemperature, s.colorTemperatureMireds);
    }
  }

  private schedule(): void {
    if (this.pending) clearTimeout(this.pending);
    this.pending = setTimeout(() => {
      this.pending = null;
      const s = this.registry.get(this.fixture.id);
      this.platform.log.info(
        `[${this.fixture.id}] HK set: on=${s.on} br=${s.brightness}` +
        (s.hue != null ? ` h=${s.hue}` : '') +
        (s.saturation != null ? ` s=${s.saturation}` : '') +
        (s.colorTemperatureMireds != null ? ` ct=${s.colorTemperatureMireds}` : ''),
      );
      this.controller.setFixture(this.fixture, s);
    }, CHARACTERISTIC_UPDATE_DELAY_MS);
  }
}
