//! GPU plumbing: one shared wgpu device, and a surface + egui renderer per window.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use winit::window::Window;

pub struct Gpu {
    pub instance: wgpu::Instance,
    pub adapter: wgpu::Adapter,
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
}

impl Gpu {
    /// `display` must be the event loop's display connection, *not* a window: wgpu keeps it for
    /// its whole lifetime, and holding a window there would keep that window alive forever.
    pub fn new(
        display: winit::event_loop::OwnedDisplayHandle,
        first_window: Arc<Window>,
    ) -> Result<(Self, wgpu::Surface<'static>)> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::VULKAN | wgpu::Backends::GL,
            ..wgpu::InstanceDescriptor::new_with_display_handle(Box::new(display))
        });
        let surface = instance.create_surface(first_window).context("create window surface")?;
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: Some(&surface),
            force_fallback_adapter: false,
            apply_limit_buckets: false,
        }))
        .context("no suitable GPU adapter")?;
        let info = adapter.get_info();
        tracing::info!(name = %info.name, backend = ?info.backend, "Using GPU adapter");
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("bastion"),
            required_limits: wgpu::Limits::downlevel_defaults().using_resolution(adapter.limits()),
            ..Default::default()
        }))
        .context("create GPU device")?;
        Ok((Self { instance, adapter, device, queue }, surface))
    }
}

/// A window's surface plus its egui state.
pub struct WindowGfx {
    pub window: Arc<Window>,
    pub surface: wgpu::Surface<'static>,
    pub config: wgpu::SurfaceConfiguration,
    pub renderer: egui_wgpu::Renderer,
    pub egui: egui_winit::State,
    pub ctx: egui::Context,
    /// When egui asked to be repainted next (animations, delayed UI updates).
    pub next_repaint: Option<std::time::Instant>,
    /// Follow egui's own repaint requests. Session windows turn this off while no overlay is
    /// shown: egui asks for another frame after every frame that had input, which over the
    /// bare remote desktop meant rendering at the mouse's event rate for nothing.
    pub follow_repaints: bool,
}

impl WindowGfx {
    pub fn new(gpu: &Gpu, window: Arc<Window>, surface: Option<wgpu::Surface<'static>>) -> Result<Self> {
        let surface = match surface {
            Some(s) => s,
            None => gpu.instance.create_surface(window.clone()).context("create window surface")?,
        };
        let caps = surface.get_capabilities(&gpu.adapter);
        // Non-sRGB target: remote pixels are already gamma-encoded, so they pass through untouched.
        let format = caps.formats.iter().copied().find(|f| !f.is_srgb()).unwrap_or(caps.formats[0]);
        let size = window.inner_size();
        let present_mode = if caps.present_modes.contains(&wgpu::PresentMode::Mailbox) {
            wgpu::PresentMode::Mailbox
        } else {
            wgpu::PresentMode::Fifo
        };
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width: size.width.max(1),
            height: size.height.max(1),
            present_mode,
            desired_maximum_frame_latency: 1,
            alpha_mode: caps.alpha_modes[0],
            color_space: wgpu::SurfaceColorSpace::Auto,
            view_formats: vec![],
        };
        surface.configure(&gpu.device, &config);
        let renderer = egui_wgpu::Renderer::new(
            &gpu.device,
            format,
            egui_wgpu::RendererOptions {
                msaa_samples: 1,
                depth_stencil_format: None,
                dithering: false,
                ..Default::default()
            },
        );
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let egui = egui_winit::State::new(
            ctx.clone(),
            egui::ViewportId::ROOT,
            &window,
            Some(window.scale_factor() as f32),
            None,
            Some(gpu.device.limits().max_texture_dimension_2d as usize),
        );
        Ok(Self { window, surface, config, renderer, egui, ctx, next_repaint: None, follow_repaints: true })
    }

    pub fn resize(&mut self, gpu: &Gpu, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        self.config.width = width;
        self.config.height = height;
        self.surface.configure(&gpu.device, &self.config);
    }

    /// Runs one egui frame and presents it.
    pub fn frame(&mut self, gpu: &Gpu, ui: impl FnMut(&mut egui::Ui)) -> egui::PlatformOutput {
        let raw = self.egui.take_egui_input(&self.window);
        let full = self.ctx.run_ui(raw, ui);
        let platform_output = full.platform_output.clone();
        self.egui.handle_platform_output(&self.window, full.platform_output);

        let ppp = full.pixels_per_point;
        let jobs = self.ctx.tessellate(full.shapes, ppp);
        let screen = egui_wgpu::ScreenDescriptor {
            size_in_pixels: [self.config.width, self.config.height],
            pixels_per_point: ppp,
        };

        // Texture deltas must always be applied (even if this frame is skipped), or egui loses them.
        let mut textures = full.textures_delta;
        for (id, deltas) in &textures.set {
            for delta in deltas {
                self.renderer.update_texture(&gpu.device, &gpu.queue, *id, delta);
            }
        }
        textures.set.clear();
        let frees = std::mem::take(&mut textures.free);
        let frame = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(f) => f,
            wgpu::CurrentSurfaceTexture::Suboptimal(f) => {
                self.surface.configure(&gpu.device, &self.config);
                f
            }
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                self.surface.configure(&gpu.device, &self.config);
                bastion_metrics::UI_FRAMES_SKIPPED.incr();
                bastion_metrics::UI_REDRAW_SURFACE.incr();
                self.window.request_redraw();
                self.free_textures(&frees);
                return platform_output;
            }
            other => {
                bastion_metrics::UI_FRAMES_SKIPPED.incr();
                tracing::debug!(state = ?std::mem::discriminant(&other), "Skipped frame");
                self.free_textures(&frees);
                return platform_output;
            }
        };
        let view = frame.texture.create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = gpu.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("egui") });
        let extra = self.renderer.update_buffers(&gpu.device, &gpu.queue, &mut encoder, &jobs, &screen);
        {
            let pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("egui"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    depth_slice: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                ..Default::default()
            });
            self.renderer.render(&mut pass.forget_lifetime(), &jobs, &screen);
        }
        gpu.queue.submit(extra.into_iter().chain(std::iter::once(encoder.finish())));
        self.window.pre_present_notify();
        gpu.queue.present(frame);
        self.free_textures(&frees);
        self.next_repaint = None;
        if let Some(v) = full.viewport_output.get(&egui::ViewportId::ROOT).filter(|_| self.follow_repaints) {
            if v.repaint_delay.is_zero() {
                bastion_metrics::UI_REDRAW_EGUI.incr();
                self.window.request_redraw();
            } else if v.repaint_delay < std::time::Duration::from_secs(60) {
                self.next_repaint = Some(std::time::Instant::now() + v.repaint_delay);
            }
        }
        platform_output
    }
}

impl WindowGfx {
    fn free_textures<'a>(&mut self, ids: impl IntoIterator<Item = &'a egui::TextureId>) {
        for id in ids {
            self.renderer.free_texture(id);
        }
    }

    /// Requests a redraw if egui's timer elapsed; returns the next pending deadline.
    pub fn tick(&mut self) -> Option<std::time::Instant> {
        match self.next_repaint {
            Some(t) if t <= std::time::Instant::now() => {
                self.next_repaint = None;
                bastion_metrics::UI_REDRAW_EGUI.incr();
                self.window.request_redraw();
                None
            }
            other => other,
        }
    }
}
