/*
    Wisecracker: A cryptanalysis framework
    Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
       
   	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.
   
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
   
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
 * Copyright: 2011 - 2012. Selective Intellect LLC. All Rights Reserved.
 * Author: Vikas Kumar
 * Date: 27th Oct 2012
 * Software: WiseCracker
 */
#include <wisecracker.h>
namespace wc {

#define LOCALCPP_INVALID_PARAMETER(FN) \
	WC_ERROR("C++ " #FN "() received invalid parameter\n")

#define LOCALCPP_ERROR(FN,ERR) \
	WC_ERROR("C++ " #FN "() returned error: %d\n", ERR)

struct Executor::Implementation {
	wc_exec_t *wce;
	CallbackInterface *cbi;
	static wc_err_t on_start(const wc_exec_t *wc, void *user)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			return _impl->cbi->on_start();
		} else {
			LOCALCPP_INVALID_PARAMETER(on_start);
			return WC_EXE_ERR_INVALID_PARAMETER;
		}
	}
	static wc_err_t on_finish(const wc_exec_t *wc, void *user)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi)
			return _impl->cbi->on_finish();
		LOCALCPP_INVALID_PARAMETER(on_finish);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static char *get_code(const wc_exec_t *wc, void *user, size_t *codelen)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			std::string code;
			char *codebuf = NULL;
			wc_err_t err = _impl->cbi->get_code(code);
			if (err == WC_EXE_OK) {
				if (code.length() == 0) {
					WC_ERROR("C++ get_code() did not return any code.\n");
					return NULL;
				}
				if (codelen)
					*codelen = code.length();
				codebuf = wc_util_strdup(code.c_str());
				if (!codebuf) {
					WC_ERROR_OUTOFMEMORY(code.length());
				}
			} else {
				if(codelen)
					*codelen = 0;
				codebuf = NULL;
				LOCALCPP_ERROR(get_code, err);
			}
			return codebuf;
		} else {
			LOCALCPP_INVALID_PARAMETER(get_code);
		}
		return NULL;
	}
	static char *get_build_options(const wc_exec_t *wc, void *user)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			std::string buildoptstr;
			char *buildopts = NULL;
			_impl->cbi->get_build_options(buildoptstr);
			if (!buildoptstr.empty()) {
				buildopts = wc_util_strdup(buildoptstr.c_str());
				if (!buildopts) {
					WC_ERROR_OUTOFMEMORY(buildoptstr.length());
				}
			} else {
				buildopts = NULL;
				WC_DEBUG("C++ get_build_options() did not return any"
						" options\n");
			}
			return buildopts;
		} else {
			LOCALCPP_INVALID_PARAMETER(get_build_options);
		}
		return NULL;
	}
	static void on_code_compile(const wc_exec_t *wc, void *user, uint8_t success)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			_impl->cbi->on_code_compile((success == 1) ? true : false);
		} else {
			LOCALCPP_INVALID_PARAMETER(on_code_compile);
		}
	}
	static uint64_t get_num_tasks(const wc_exec_t *wc, void *user)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			return _impl->cbi->get_num_tasks();
		}
		LOCALCPP_INVALID_PARAMETER(get_num_tasks);
		return 0;
	}
	static uint32_t get_task_range_multiplier(const wc_exec_t *wc, void *user)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			return _impl->cbi->get_task_multiplier();
		}
		LOCALCPP_INVALID_PARAMETER(get_task_multiplier);
		return 0;
	}
	static wc_err_t get_global_data(const wc_exec_t *wc, void *user,
			wc_data_t *out)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && out) {
			return _impl->cbi->get_global_data(*out);
		}
		LOCALCPP_INVALID_PARAMETER(get_global_data);
		return WC_EXE_ERR_INVALID_PARAMETER;

	}
	static wc_err_t on_receive_global_data(const wc_exec_t *wc, void *user,
			const wc_data_t *gdata)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && gdata) {
			return _impl->cbi->on_receive_global_data(*gdata);
		}
		LOCALCPP_INVALID_PARAMETER(on_receive_global_data);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static wc_err_t on_device_start(const wc_exec_t *wc, wc_cldev_t *dev,
			uint32_t devindex, void *user, const wc_data_t *gdata)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && dev && gdata) {
			return _impl->cbi->on_device_start(*dev, devindex, *gdata);
		}
		LOCALCPP_INVALID_PARAMETER(on_device_start);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static wc_err_t on_device_finish(const wc_exec_t *wc, wc_cldev_t *dev,
			uint32_t devindex, void *user, const wc_data_t *gdata)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && dev && gdata) {
			return _impl->cbi->on_device_finish(*dev, devindex, *gdata);
		}
		LOCALCPP_INVALID_PARAMETER(on_device_finish);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static wc_err_t on_device_range_exec(const wc_exec_t *wc, wc_cldev_t *dev,
			uint32_t devindex, void *user, const wc_data_t *gdata,
			uint64_t start, uint64_t end, cl_event *out_event)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && dev && gdata) {
			CallbackInterface::Range range;
			range.start = start;
			range.end = end;
			return _impl->cbi->on_device_range_exec(*dev, devindex, *gdata,
													range, out_event);
		}
		LOCALCPP_INVALID_PARAMETER(on_device_range_exec);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static wc_err_t on_device_range_done(const wc_exec_t *wc, wc_cldev_t *dev,
			uint32_t devindex, void *user, const wc_data_t *gdata,
			uint64_t start, uint64_t end, wc_data_t *results)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && dev && gdata && results) {
			CallbackInterface::Range range;
			range.start = start;
			range.end = end;
			return _impl->cbi->on_device_range_done(*dev, devindex, *gdata,
													range, *results);
		}
		LOCALCPP_INVALID_PARAMETER(on_device_range_done);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static wc_err_t on_receive_range_results(const wc_exec_t *wc, void *user,
			uint64_t start, uint64_t end, wc_err_t slverr,
			const wc_data_t *results)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && results) {
			CallbackInterface::Range range;
			range.start = start;
			range.end = end;
			return _impl->cbi->on_receive_range_results(range, slverr,
														*results);
		}
		LOCALCPP_INVALID_PARAMETER(on_receive_range_results);
		return WC_EXE_ERR_INVALID_PARAMETER;
	}
	static void free_global_data(const wc_exec_t *wc, void *user,
			wc_data_t *gdata)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi && gdata) {
			_impl->cbi->free_global_data(*gdata);
		} else {
			LOCALCPP_INVALID_PARAMETER(free_global_data);
		}
	}
	static void progress(float percent, void *user)
	{
		Executor::Implementation *_impl = (Executor::Implementation *)user;
		if (_impl && _impl->cbi) {
			_impl->cbi->progress(percent);
		} else {
			LOCALCPP_INVALID_PARAMETER(progress);
		}
	}
};

Executor::Executor(int *argc, char ***argv)
{
	_impl = new Implementation;
	if (!_impl)
		throw std::runtime_error("Out of memory!");
	_impl->wce = ::wc_executor_init(argc, argv);
	if (!_impl->wce) {
		throw std::runtime_error("executor initialization failed");
	}
}

Executor::~Executor()
{
	if (_impl) {
		if (_impl->wce) {
			::wc_executor_destroy(_impl->wce);
			_impl->wce = NULL;
		}
		delete _impl;
	}
	_impl = NULL;
}

wc_err_t Executor::setup(CallbackInterface *cb)
{
	if (!cb)
		return WC_EXE_ERR_INVALID_PARAMETER;

	if (_impl && _impl->wce && cb) {
		wc_exec_callbacks_t cbs;
		_impl->cbi = cb;
		cb->_executor = this;
		::memset(&cbs, 0, sizeof(cbs));
		cbs.user = (void *)_impl;
		cbs.max_devices = cb->max_devices();
		cbs.device_type = cb->device_type();
		cbs.on_start = Executor::Implementation::on_start;
		cbs.on_finish = Executor::Implementation::on_finish;
		cbs.get_code = Executor::Implementation::get_code;
		cbs.get_build_options = Executor::Implementation::get_build_options;
		cbs.on_code_compile = Executor::Implementation::on_code_compile;
		cbs.get_num_tasks = Executor::Implementation::get_num_tasks;
		cbs.get_task_range_multiplier =
			Executor::Implementation::get_task_range_multiplier;
		cbs.get_global_data = Executor::Implementation::get_global_data;
		cbs.on_receive_global_data =
			Executor::Implementation::on_receive_global_data;
		cbs.on_device_start = Executor::Implementation::on_device_start;
		cbs.on_device_finish = Executor::Implementation::on_device_finish;
		cbs.on_device_range_exec = Executor::Implementation::on_device_range_exec;
		cbs.on_device_range_done = Executor::Implementation::on_device_range_done;
		cbs.on_receive_range_results =
			Executor::Implementation::on_receive_range_results;
		cbs.free_global_data = Executor::Implementation::free_global_data;
		cbs.progress = Executor::Implementation::progress;
		return ::wc_executor_setup(_impl->wce, &cbs);
	}
	return WC_EXE_ERR_BAD_STATE;
}

wc_err_t Executor::run()
{
	if (_impl && _impl->wce)
		return ::wc_executor_run(_impl->wce);	
	return WC_EXE_ERR_INVALID_PARAMETER;
}

int Executor::num_systems() const
{
	if (_impl && _impl->wce)
		return ::wc_executor_num_systems(_impl->wce);
	return -1;
}

int Executor::my_id() const
{
	if (_impl && _impl->wce)
		return ::wc_executor_system_id(_impl->wce);
	return -1;
}

uint64_t Executor::num_tasks() const
{
	if (_impl && _impl->wce)
		return ::wc_executor_num_tasks(_impl->wce);
	return 0;
}

uint32_t Executor::num_system_devices() const
{
	if (_impl && _impl->wce)
		return ::wc_executor_num_devices(_impl->wce);
	return 0;
}

void Executor::dump() const
{
	if (_impl && _impl->wce)
		::wc_executor_dump(_impl->wce);
}

} // end of namespace wc
