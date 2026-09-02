# Vendored shadcn/ui Components Catalog

These 62 components are vendored directly on disk in `src/components/ui/` and `src/hooks/`. They are not installed from node_modules; they are editable local copies. Import using the pattern `@/components/ui/<filename>` (e.g., `@/components/ui/button` for button.tsx) or `@/hooks/use-mobile` for the hook.

## Components by File

| Component File | Exports | External Dependencies |
|---|---|---|
| accordion.tsx | Accordion, AccordionContent, AccordionItem, AccordionTrigger | — |
| alert-dialog.tsx | AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogMedia, AlertDialogOverlay, AlertDialogPortal, AlertDialogTitle, AlertDialogTrigger | — |
| alert.tsx | Alert, AlertAction, AlertDescription, AlertTitle | class-variance-authority |
| aspect-ratio.tsx | AspectRatio | — |
| attachment.tsx | Attachment, AttachmentAction, AttachmentActions, AttachmentContent, AttachmentDescription, AttachmentGroup, AttachmentMedia, AttachmentTitle, AttachmentTrigger | class-variance-authority |
| avatar.tsx | Avatar, AvatarBadge, AvatarFallback, AvatarGroup, AvatarGroupCount, AvatarImage | — |
| badge.tsx | Badge, badgeVariants | class-variance-authority |
| breadcrumb.tsx | Breadcrumb, BreadcrumbEllipsis, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator | — |
| bubble.tsx | Bubble, BubbleContent, BubbleGroup, BubbleReactions | class-variance-authority |
| button-group.tsx | ButtonGroup, ButtonGroupSeparator, ButtonGroupText, buttonGroupVariants | class-variance-authority |
| button.tsx | Button, buttonVariants | class-variance-authority |
| calendar.tsx | Calendar, CalendarDayButton | — |
| card.tsx | Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle | — |
| carousel.tsx | Carousel, CarouselApi, CarouselContent, CarouselItem, CarouselNext, CarouselPrevious, useCarousel | embla-carousel-react |
| chart.tsx | ChartConfig, ChartContainer, ChartLegend, ChartLegendContent, ChartStyle, ChartTooltip, ChartTooltipContent | recharts |
| checkbox.tsx | Checkbox | — |
| collapsible.tsx | Collapsible, CollapsibleContent, CollapsibleTrigger | — |
| combobox.tsx | Combobox, ComboboxChip, ComboboxChips, ComboboxChipsInput, ComboboxCollection, ComboboxContent, ComboboxEmpty, ComboboxGroup, ComboboxInput, ComboboxItem, ComboboxLabel, ComboboxList, ComboboxSeparator, ComboboxTrigger, ComboboxValue, useComboboxAnchor | — |
| command.tsx | Command, CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator, CommandShortcut | cmdk |
| context-menu.tsx | ContextMenu, ContextMenuCheckboxItem, ContextMenuContent, ContextMenuGroup, ContextMenuItem, ContextMenuLabel, ContextMenuPortal, ContextMenuRadioGroup, ContextMenuRadioItem, ContextMenuSeparator, ContextMenuShortcut, ContextMenuSub, ContextMenuSubContent, ContextMenuSubTrigger, ContextMenuTrigger | — |
| dialog.tsx | Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogOverlay, DialogPortal, DialogTitle, DialogTrigger | — |
| direction.tsx | DirectionProvider, useDirection | — (re-exports from @base-ui/react/direction-provider) |
| drawer.tsx | Drawer, DrawerClose, DrawerContent, DrawerDescription, DrawerFooter, DrawerHeader, DrawerOverlay, DrawerPortal, DrawerSwipeHandle, DrawerTitle, DrawerTrigger | — |
| dropdown-menu.tsx | DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuLabel, DropdownMenuPortal, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuShortcut, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuTrigger | — |
| empty.tsx | Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle | class-variance-authority |
| field.tsx | Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSeparator, FieldSet, FieldTitle | class-variance-authority |
| hover-card.tsx | HoverCard, HoverCardContent, HoverCardTrigger | — |
| input-group.tsx | InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput, InputGroupText, InputGroupTextarea | class-variance-authority |
| input-otp.tsx | InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot | input-otp |
| input.tsx | Input | — |
| item.tsx | Item, ItemActions, ItemContent, ItemDescription, ItemFooter, ItemGroup, ItemHeader, ItemMedia, ItemSeparator, ItemTitle | class-variance-authority |
| kbd.tsx | Kbd, KbdGroup | — |
| label.tsx | Label | — |
| marker.tsx | Marker, MarkerContent, MarkerIcon, markerVariants | class-variance-authority |
| menubar.tsx | Menubar, MenubarCheckboxItem, MenubarContent, MenubarGroup, MenubarItem, MenubarLabel, MenubarMenu, MenubarPortal, MenubarRadioGroup, MenubarRadioItem, MenubarSeparator, MenubarShortcut, MenubarSub, MenubarSubContent, MenubarSubTrigger, MenubarTrigger | — |
| message-scroller.tsx | MessageScroller, MessageScrollerButton, MessageScrollerContent, MessageScrollerItem, MessageScrollerProvider, MessageScrollerViewport, useMessageScroller, useMessageScrollerScrollable, useMessageScrollerVisibility | @shadcn/react/message-scroller |
| message.tsx | Message, MessageAvatar, MessageContent, MessageFooter, MessageGroup, MessageHeader | — |
| native-select.tsx | NativeSelect, NativeSelectOptGroup, NativeSelectOption | — |
| navigation-menu.tsx | NavigationMenu, NavigationMenuContent, NavigationMenuIndicator, NavigationMenuItem, NavigationMenuLink, NavigationMenuList, NavigationMenuPositioner, NavigationMenuTrigger, navigationMenuTriggerStyle | class-variance-authority |
| pagination.tsx | Pagination, PaginationContent, PaginationEllipsis, PaginationItem, PaginationLink, PaginationNext, PaginationPrevious | — |
| popover.tsx | Popover, PopoverContent, PopoverDescription, PopoverHeader, PopoverTitle, PopoverTrigger | — |
| progress.tsx | Progress, ProgressIndicator, ProgressLabel, ProgressTrack, ProgressValue | — |
| questionnaire.tsx | Questionnaire, QuestionnaireActions, QuestionnaireChoice, QuestionnaireChoiceDescription, QuestionnaireChoices, QuestionnaireDescription, QuestionnaireError, QuestionnaireInput, QuestionnaireItem, QuestionnaireNext, QuestionnairePrevious, QuestionnaireProgress, QuestionnaireSkip, QuestionnaireSubmit, QuestionnaireTitle | — |
| radio-group.tsx | RadioGroup, RadioGroupItem | — |
| resizable.tsx | ResizableHandle, ResizablePanel, ResizablePanelGroup | — |
| scroll-area.tsx | ScrollArea, ScrollBar | — |
| select.tsx | Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectScrollDownButton, SelectScrollUpButton, SelectSeparator, SelectTrigger, SelectValue | — |
| separator.tsx | Separator | — |
| sheet.tsx | Sheet, SheetClose, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetTrigger | — |
| sidebar.tsx | Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupAction, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarInput, SidebarInset, SidebarMenu, SidebarMenuAction, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem, SidebarMenuSkeleton, SidebarMenuSub, SidebarMenuSubButton, SidebarMenuSubItem, SidebarProvider, SidebarRail, SidebarSeparator, SidebarTrigger, useSidebar | class-variance-authority |
| skeleton.tsx | Skeleton | — |
| slider.tsx | Slider | — |
| spinner.tsx | Spinner | — |
| switch.tsx | Switch | — |
| table.tsx | Table, TableBody, TableCaption, TableCell, TableFooter, TableHead, TableHeader, TableRow | — |
| tabs.tsx | Tabs, TabsContent, TabsList, TabsTrigger, tabsListVariants | class-variance-authority |
| textarea.tsx | Textarea | — |
| toast.tsx | Toast, ToastAction, ToastClose, ToastContent, ToastDescription, ToastPortal, ToastProvider, ToastTitle, ToastViewport, Toaster, createToastManager, toast, useToastManager | — |
| toggle-group.tsx | ToggleGroup, ToggleGroupItem | class-variance-authority |
| toggle.tsx | Toggle, toggleVariants | class-variance-authority |
| tooltip.tsx | Tooltip, TooltipContent, TooltipProvider, TooltipTrigger | — |
| use-mobile.ts | useIsMobile | — |

## Grouped by Purpose

**Forms & Input**
- input.tsx (Input)
- textarea.tsx (Textarea)
- checkbox.tsx (Checkbox)
- radio-group.tsx (RadioGroup, RadioGroupItem)
- switch.tsx (Switch)
- label.tsx (Label)
- field.tsx (Field, FieldContent, FieldDescription, etc.)
- input-otp.tsx (InputOTP, InputOTPGroup, etc.)
- input-group.tsx (InputGroup, InputGroupAddon, etc.)
- native-select.tsx (NativeSelect, NativeSelectOptGroup, etc.)
- select.tsx (Select, SelectContent, SelectTrigger, etc.)

**Overlays & Dialogs**
- dialog.tsx (Dialog, DialogContent, DialogTrigger, etc.)
- alert-dialog.tsx (AlertDialog, AlertDialogContent, etc.)
- drawer.tsx (Drawer, DrawerContent, DrawerTrigger, etc.)
- popover.tsx (Popover, PopoverContent, PopoverTrigger)
- hover-card.tsx (HoverCard, HoverCardContent, HoverCardTrigger)
- tooltip.tsx (Tooltip, TooltipContent, TooltipTrigger, TooltipProvider)
- sheet.tsx (Sheet, SheetContent, SheetTrigger, etc.)

**Navigation & Menus**
- button.tsx (Button, buttonVariants)
- button-group.tsx (ButtonGroup, ButtonGroupSeparator, etc.)
- breadcrumb.tsx (Breadcrumb, BreadcrumbItem, etc.)
- pagination.tsx (Pagination, PaginationItem, etc.)
- tabs.tsx (Tabs, TabsList, TabsTrigger, TabsContent, etc.)
- dropdown-menu.tsx (DropdownMenu, DropdownMenuContent, etc.)
- context-menu.tsx (ContextMenu, ContextMenuContent, etc.)
- menubar.tsx (Menubar, MenubarContent, etc.)
- navigation-menu.tsx (NavigationMenu, NavigationMenuContent, etc.)
- sidebar.tsx (Sidebar, SidebarContent, SidebarProvider, etc.)
- toggle.tsx (Toggle, toggleVariants)
- toggle-group.tsx (ToggleGroup, ToggleGroupItem)

**Data Display**
- table.tsx (Table, TableHead, TableBody, etc.)
- card.tsx (Card, CardHeader, CardContent, CardFooter, etc.)
- badge.tsx (Badge, badgeVariants)
- avatar.tsx (Avatar, AvatarImage, AvatarFallback, etc.)
- empty.tsx (Empty, EmptyHeader, EmptyTitle, etc.)
- item.tsx (Item, ItemContent, ItemDescription, etc.)
- bubble.tsx (Bubble, BubbleContent, BubbleGroup, etc.)
- message.tsx (Message, MessageContent, MessageAvatar, etc.)
- marker.tsx (Marker, MarkerContent, markerVariants)

**Feedback & Status**
- alert.tsx (Alert, AlertTitle, AlertDescription)
- progress.tsx (Progress, ProgressTrack, ProgressValue)
- skeleton.tsx (Skeleton)
- spinner.tsx (Spinner)
- toast.tsx (Toast, ToastContent, Toaster, ToastProvider, etc.)

**Layout**
- separator.tsx (Separator)
- scroll-area.tsx (ScrollArea, ScrollBar)
- resizable.tsx (ResizablePanel, ResizableHandle, ResizablePanelGroup)
- aspect-ratio.tsx (AspectRatio)
- carousel.tsx (Carousel, CarouselContent, CarouselItem, etc.)
- collapsible.tsx (Collapsible, CollapsibleTrigger, CollapsibleContent)
- accordion.tsx (Accordion, AccordionItem, AccordionTrigger, AccordionContent)

**Chat & Messaging**
- message-scroller.tsx (MessageScroller, MessageScrollerContent, MessageScrollerProvider, etc.)

**Utilities & Specialized**
- combobox.tsx (Combobox, ComboboxContent, ComboboxInput, etc.)
- command.tsx (Command, CommandInput, CommandItem, etc.)
- calendar.tsx (Calendar, CalendarDayButton)
- chart.tsx (ChartContainer, ChartTooltip, ChartLegend, etc.)
- attachment.tsx (Attachment, AttachmentContent, etc.)
- questionnaire.tsx (Questionnaire, QuestionnaireChoice, etc.)
- kbd.tsx (Kbd, KbdGroup)
- direction.tsx (DirectionProvider, useDirection)
- use-mobile.ts (useIsMobile)

## Components Requiring Context Providers

The following components must have their corresponding provider mounted higher in the React tree to function properly:

- **DirectionProvider** (from direction.tsx) — wrap your app to enable RTL/LTR direction support via `useDirection()`
- **TooltipProvider** (from tooltip.tsx) — mount once at app root to enable all Tooltip components
- **SidebarProvider** (from sidebar.tsx) — mount at app root to enable sidebar state management and `useSidebar()` hook
- **ToastProvider** (from toast.tsx) — mount at app root via the `Toaster` component; use `createToastManager()` and the `toast` manager to show toasts
- **MessageScrollerProvider** (from message-scroller.tsx) — wrap MessageScroller components to enable auto-scroll and visibility hooks
