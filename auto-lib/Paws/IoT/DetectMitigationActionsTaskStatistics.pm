# Generated by default/object.tt
package Paws::IoT::DetectMitigationActionsTaskStatistics;
  use Moose;
  has ActionsExecuted => (is => 'ro', isa => 'Int', request_name => 'actionsExecuted', traits => ['NameInRequest']);
  has ActionsFailed => (is => 'ro', isa => 'Int', request_name => 'actionsFailed', traits => ['NameInRequest']);
  has ActionsSkipped => (is => 'ro', isa => 'Int', request_name => 'actionsSkipped', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoT::DetectMitigationActionsTaskStatistics

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoT::DetectMitigationActionsTaskStatistics object:

  $service_obj->Method(Att1 => { ActionsExecuted => $value, ..., ActionsSkipped => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoT::DetectMitigationActionsTaskStatistics object:

  $result = $service_obj->Method(...);
  $result->Att1->ActionsExecuted

=head1 DESCRIPTION

The statistics of a mitigation action task.

=head1 ATTRIBUTES


=head2 ActionsExecuted => Int

The actions that were performed.


=head2 ActionsFailed => Int

The actions that failed.


=head2 ActionsSkipped => Int

The actions that were skipped.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoT>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

