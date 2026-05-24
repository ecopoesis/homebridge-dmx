// ZoneFixture — virtual HomeKit Lightbulb that aggregates a set of member
// fixtures.
//
// Reads: each .onGet returns the MAJORITY value of that characteristic
// across the zone's members. Ties are broken in favour of the value held
// by the alphabetically-first member. This gives a deterministic display
// even when members are in split states.
//
// Writes: each .onSet updates every member's state in the registry (which
// fires per-member change events so the individual fixture accessories
// refresh their own HomeKit displays), then triggers the controller for
// each member so the DMX wire reflects the change.
//
// When ANY member's state changes (by any path), the zone's HomeKit
// characteristics push the new majority — so zones containing overlapping
// members stay coherent with each other.

import type {
  CharacteristicValue,
  PlatformAccessory,
  Service,
} from 'homebridge';

import { Fixture, Zone } from './config.js';
import { HKCharacteristic, HomeKitLightState } from './color/types.js';
import { StickController } from './controller.js';
import type { DmxPlatform } from './platform.js';
import { CHARACTERISTIC_UPDATE_DELAY_MS } from './settings.js';
import { StateRegistry, pickMajority } from './stateRegistry.js';

export class ZoneFixture {
  private pending: NodeJS.Timeout | null = null;
  private refreshPending: NodeJS.Timeout | null = null;
  private bulb: Service;

  constructor(
    private readonly platform: DmxPlatform,
    accessory: PlatformAccessory,
    private readonly zone: Zone,
    private readonly controllers: Map<string, StickController>,
    private readonly registry: StateRegistry,
  ) {
    const C = platform.Characteristic;
    const info = accessory.getService(platform.Service.AccessoryInformation);
    info?.setCharacteristic(C.Manufacturer, 'DMX')
        ?.setCharacteristic(C.Model, `Zone (${zone.members.length} fixtures)`)
        ?.setCharacteristic(C.SerialNumber, `zone-${zone.id}`);

    this.bulb =
      accessory.getService(platform.Service.Lightbulb)
      ?? accessory.addService(platform.Service.Lightbulb, zone.name);

    this.bulb.setCharacteristic(C.Name, zone.name);

    const has = (k: HKCharacteristic): boolean => zone.characteristics.includes(k);

    this.bulb.getCharacteristic(C.On)
      .onGet(() => this.majorityState().on)
      .onSet((v) => this.applyToMembers({ on: Boolean(v) }));

    if (has('Brightness')) {
      this.bulb.getCharacteristic(C.Brightness)
        .onGet(() => this.majorityState().brightness)
        .onSet((v: CharacteristicValue) => this.applyToMembers({ brightness: Number(v) }));
    }
    if (has('Hue')) {
      this.bulb.getCharacteristic(C.Hue)
        .onGet(() => this.majorityState().hue ?? 0)
        .onSet((v) => this.applyToMembers({ hue: Number(v) }));
    }
    if (has('Saturation')) {
      this.bulb.getCharacteristic(C.Saturation)
        .onGet(() => this.majorityState().saturation ?? 0)
        .onSet((v) => this.applyToMembers({ saturation: Number(v) }));
    }
    if (has('ColorTemperature')) {
      this.bulb.getCharacteristic(C.ColorTemperature)
        .onGet(() => this.majorityState().colorTemperatureMireds ?? 200)
        .onSet((v) => this.applyToMembers({
          colorTemperatureMireds: Number(v),
          saturation: 0,
        }));
    }

    // Refresh on any member change.
    const memberIds = new Set(zone.members.map((m) => m.id));
    registry.onChange((id) => {
      if (memberIds.has(id)) this.scheduleRefresh();
    });
  }

  /** Compute majority state across members, per characteristic. */
  private majorityState(): HomeKitLightState {
    const ss = this.zone.members.map((m) => ({ id: m.id, state: this.registry.get(m.id) }));
    return {
      on:                       pickMajority(ss.map((s) => ({ id: s.id, v: s.state.on }))) ?? false,
      brightness:               pickMajority(ss.map((s) => ({ id: s.id, v: s.state.brightness }))) ?? 100,
      hue:                      pickMajority(ss.map((s) => ({ id: s.id, v: s.state.hue }))),
      saturation:               pickMajority(ss.map((s) => ({ id: s.id, v: s.state.saturation }))),
      colorTemperatureMireds:   pickMajority(ss.map((s) => ({ id: s.id, v: s.state.colorTemperatureMireds }))),
    };
  }

  /** A HomeKit set on the zone: build the new state from the current
   *  majority + the patch the user is applying, write it into every
   *  member, and trigger the controller after a small debounce so
   *  multi-characteristic dispatch coalesces. */
  private applyToMembers(patch: Partial<HomeKitLightState>): void {
    const next = { ...this.majorityState(), ...patch };
    // Push the next state into every member's registry entry. This fires
    // per-fixture change events so the individual StickFixture accessories
    // refresh their own HomeKit displays.
    for (const m of this.zone.members) {
      this.registry.update(m.id, next);
    }
    this.scheduleDispatch();
  }

  /** Debounced controller dispatch. Sends current registry state for each
   *  member to the appropriate StickController. */
  private scheduleDispatch(): void {
    if (this.pending) clearTimeout(this.pending);
    this.pending = setTimeout(() => {
      this.pending = null;
      const s = this.majorityState();
      this.platform.log.info(
        `[zone:${this.zone.id}] HK set: on=${s.on} br=${s.brightness}` +
        (s.hue != null ? ` h=${s.hue}` : '') +
        (s.saturation != null ? ` s=${s.saturation}` : '') +
        (s.colorTemperatureMireds != null ? ` ct=${s.colorTemperatureMireds}` : '') +
        ` → ${this.zone.members.length} members`,
      );
      for (const m of this.zone.members) {
        const c = this.controllers.get(m.controller.id);
        if (!c) {
          this.platform.log.error(`zone "${this.zone.id}": no controller for "${m.id}"`);
          continue;
        }
        c.setFixture(m, this.registry.get(m.id));
      }
    }, CHARACTERISTIC_UPDATE_DELAY_MS);
  }

  /** Debounced refresh: when members change, push the new majority to
   *  the zone's HomeKit characteristics. */
  private scheduleRefresh(): void {
    if (this.refreshPending) clearTimeout(this.refreshPending);
    this.refreshPending = setTimeout(() => {
      this.refreshPending = null;
      const s = this.majorityState();
      const C = this.platform.Characteristic;
      this.bulb.updateCharacteristic(C.On, s.on);
      if (this.zone.characteristics.includes('Brightness')) {
        this.bulb.updateCharacteristic(C.Brightness, s.brightness);
      }
      if (this.zone.characteristics.includes('Hue') && s.hue != null) {
        this.bulb.updateCharacteristic(C.Hue, s.hue);
      }
      if (this.zone.characteristics.includes('Saturation') && s.saturation != null) {
        this.bulb.updateCharacteristic(C.Saturation, s.saturation);
      }
      if (this.zone.characteristics.includes('ColorTemperature') && s.colorTemperatureMireds != null) {
        this.bulb.updateCharacteristic(C.ColorTemperature, s.colorTemperatureMireds);
      }
    }, CHARACTERISTIC_UPDATE_DELAY_MS);
  }
}

// Silence "Fixture imported but unused" — kept for potential future use.
export type _MemberRef = Fixture;
