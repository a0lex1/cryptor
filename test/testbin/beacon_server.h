#pragma once

#include <iostream>
#include <format>
#include <stdexcept>
#include <string>
#include <sstream>
#include <memory>
#include <windows.h>

class Beacon {
public:
  virtual ~Beacon() {
    close_yo();
  }
  Beacon(const char* beacon_name) {
    beacon_name_ = beacon_name;
  }
  const std::string& get_name() const { return beacon_name_; }
  virtual void open() = 0;
  virtual bool child_reported() = 0; // rename to check_report 
  virtual void close_yo() { }
private:
  Beacon(const Beacon&) = delete;//noncopyable
  Beacon& operator=(const Beacon&) = delete;
private:
  std::string beacon_name_;
};

class BeaconThroughEvent: public Beacon {
public:
  virtual ~BeaconThroughEvent() = default;

  using Beacon::Beacon;

  virtual std::string get_uid() = 0;

  void open() override {
    std::string uid_str = get_uid();
    std::string event_name = "TesterBeacon_" + uid_str + "_" + get_name();

    hEvent_ = CreateEventA(NULL, TRUE, FALSE, event_name.c_str());
    if (!hEvent_) {
      throw std::runtime_error(std::format("CreateEventW({}) failed, err {}", event_name, GetLastError()));
    }
  }
  bool child_reported() override {
    DWORD w = WaitForSingleObject(hEvent_, 0);
    return (w == WAIT_OBJECT_0);
  }
  void close_yo() override {
    if (hEvent_) {
      if (!CloseHandle(hEvent_)) {
        throw std::runtime_error(std::format("CloseHandle(%p) failed, err %d", hEvent_, GetLastError()));
      }
      hEvent_ = NULL;
    }
  }
private:
  BeaconThroughEvent(const BeaconThroughEvent&) = delete;//noncopyable
  BeaconThroughEvent& operator=(const BeaconThroughEvent&) = delete;

private:
  HANDLE hEvent_{ NULL };
};

class BeaconThroughEnvvar : public BeaconThroughEvent {
public:
  virtual ~BeaconThroughEnvvar() = default;

  using BeaconThroughEvent::BeaconThroughEvent;

  void open() override {
    // Use our pid (tester's pid) as UID
    // It's too complicated to access parent pid so we put it env opaque env var
    // and create child process having it set (so it's inherited)
    SetEnvironmentVariableA("__#TESTER_UID", get_uid().c_str());
    BeaconThroughEvent::open();
  }
  //bool child_reported() override
  void close_yo() override {
    SetEnvironmentVariableA("__#TESTER_UID", NULL); // unset env var
    BeaconThroughEvent::close_yo();
  }
  std::string get_uid() override {
    ULONG_PTR mypid = GetCurrentProcessId();
    std::stringstream ss;
    ss << mypid;
    return ss.str();
  }
private:
  std::string uid_str_;
};


class BeaconManager {
public:
  ~BeaconManager() {
    close_all();
  }
  BeaconManager(const std::string& pseudoname): pseudoname_(pseudoname) {

  }

  void add_beacon(const char* name) {
    beacons_.push_back(std::make_shared<BeaconThroughEnvvar>(name));
  }
  void open_all() {
    for (auto& beacon : beacons_) {
      beacon->open();
    }
  }
  void close_all() {
    for (auto& beacon : beacons_) {
      beacon->open();
    }
  }
  void ensure_all_beacons_reported() {
    std::vector<std::shared_ptr<Beacon>> not_reported_beacons;
    for (auto& beacon : beacons_) {
      if (!beacon->child_reported()) {
        not_reported_beacons.push_back(beacon);
      }
      else {
        std::cout << "  ok, reported beacon - " << beacon->get_name() << "\n";
      }
    }
    if (not_reported_beacons.size()) {
      for (auto& beacon : not_reported_beacons) {
        std::cout << "BeacomMgr:  !!! NOT REPORTED BEACON IN MGR[" << pseudoname_ << "] - " << beacon->get_name() << "\n";
      }
      throw std::runtime_error("not all beacons reported, see log");
    }
    if (beacons_.size()) {
      std::cout << "BeaconMgr: all " << beacons_.size() << " beacons in mgr [" << pseudoname_ << "] have reported\n";
    }
  }
private:
  std::string pseudoname_;
  std::vector<std::shared_ptr<Beacon>> beacons_;
};



